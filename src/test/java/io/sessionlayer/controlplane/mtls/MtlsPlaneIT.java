package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.grpc.v1.ClientHello;
import io.sessionlayer.controlplane.grpc.v1.ComponentInfo;
import io.sessionlayer.controlplane.grpc.v1.GatewayIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.HandshakeGrpc;
import io.sessionlayer.controlplane.grpc.v1.RenewGatewayIdentityRequest;
import io.sessionlayer.controlplane.grpc.v1.ServerHello;
import io.sessionlayer.controlplane.protocol.ProtocolVersions;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Part A — the mTLS gRPC plane + version negotiation over mTLS. Proves a valid
 * peer connects and negotiates 1.1, every rejection case fails closed (no
 * plaintext/unauthenticated fallback), the N-1 window resolves 1.0, and a hung
 * peer is bounded by the server's TLS handshake timeout.
 */
class MtlsPlaneIT extends AbstractMtlsIT {

	@Test
	void validPeerConnectsAndNegotiatesOnePointOne() {
		EnrolledGateway gateway = enroll("gw-negotiate");
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			ServerHello reply = HandshakeGrpc.newBlockingStub(channel).negotiate(hello(1, 0, 1, 1));
			assertThat(reply.getSelected().getMajor()).isEqualTo(1);
			assertThat(reply.getSelected().getMinor()).isEqualTo(1);
		} finally {
			shutdown(channel);
		}
	}

	@Test
	void n1PeerNegotiatesOnePointZero() {
		// A Gateway that has not upgraded advertises max 1.0; the 1.1 CP still resolves
		// 1.0.
		EnrolledGateway gateway = enroll("gw-n1");
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			ServerHello reply = HandshakeGrpc.newBlockingStub(channel).negotiate(hello(1, 0, 1, 0));
			assertThat(reply.getSelected().getMinor()).isZero();
		} finally {
			shutdown(channel);
		}
	}

	@Test
	void tls12ClientIsRefused() {
		// The server is TLS-1.3-only (MtlsServerContext.protocols("TLSv1.3")). A
		// TLS-1.2-only
		// client cannot complete the handshake, so even the bootstrap negotiate fails
		// closed (L2).
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(),
				MtlsTestSupport.tls12ClientContext(caCertificate()));
		try {
			StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
					() -> HandshakeGrpc.newBlockingStub(channel).negotiate(hello(1, 0, 1, 1)));
			assertThat(error.getStatus().getCode()).isIn(Status.Code.UNAVAILABLE, Status.Code.INTERNAL);
		} finally {
			shutdown(channel);
		}
	}

	@Test
	void noClientCertIsRefusedOnMtlsRequiredRpcButBootstrapWorks() {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), null, null);
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			// Bootstrap tier (Handshake) is reachable without a client cert.
			ServerHello reply = HandshakeGrpc.newBlockingStub(channel).negotiate(hello(1, 0, 1, 1));
			assertThat(reply.getSelected().getMinor()).isEqualTo(1);
			// mTLS-required tier (Renew) fails closed.
			StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
					() -> GatewayIdentityGrpc.newBlockingStub(channel).renewGatewayIdentity(renewRequest()));
			assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
		} finally {
			shutdown(channel);
		}
	}

	@Test
	void wrongCaClientCertFailsClosed() {
		// A client cert not chained to the internal CA: the TLS handshake is rejected.
		KeyPair rogue = MtlsTestSupport.generateEcKeyPair();
		X509Certificate selfSigned = X509Certificates.selfSignCa("rogue", rogue.getPublic(), rogue.getPrivate(),
				BigInteger.ONE, Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), selfSigned, rogue.getPrivate());
		assertConnectionRefused(ssl);
	}

	@Test
	void expiredClientCertFailsClosed() {
		KeyPair keyPair = MtlsTestSupport.generateEcKeyPair();
		X509Certificate expired = mintClientCert(keyPair.getPublic(), UUID.randomUUID(),
				Instant.now().minus(10, ChronoUnit.DAYS), Instant.now().minus(1, ChronoUnit.DAYS));
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), expired, keyPair.getPrivate());
		assertConnectionRefused(ssl);
	}

	@Test
	void unknownSanIdentityIsRefusedOnMtlsRequiredRpc() {
		// A valid CA-issued client cert, but its SAN gateway id is not a known
		// identity.
		KeyPair keyPair = MtlsTestSupport.generateEcKeyPair();
		X509Certificate cert = mintClientCert(keyPair.getPublic(), UUID.randomUUID(), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(3600));
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), cert, keyPair.getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
					() -> GatewayIdentityGrpc.newBlockingStub(channel).renewGatewayIdentity(renewRequest()));
			assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
		} finally {
			shutdown(channel);
		}
	}

	@Test
	void plaintextIsRefused() {
		// No plaintext listener: a plaintext client cannot complete an RPC.
		ManagedChannel channel = MtlsTestSupport.plaintextChannel(grpcPort());
		try {
			StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
					() -> HandshakeGrpc.newBlockingStub(channel).negotiate(hello(1, 0, 1, 1)));
			assertThat(error.getStatus().getCode()).isIn(Status.Code.UNAVAILABLE, Status.Code.INTERNAL);
		} finally {
			shutdown(channel);
		}
	}

	@Test
	void hungPeerIsBoundedByHandshakeTimeout() throws Exception {
		// A peer that opens TCP but never completes the TLS handshake must be dropped
		// by
		// the server (never hangs a handshake). We wait comfortably longer than the
		// server's handshake timeout and require the connection to be closed.
		try (Socket socket = new Socket()) {
			socket.connect(new InetSocketAddress("localhost", grpcPort()), 2000);
			socket.setSoTimeout(20000);
			InputStream in = socket.getInputStream();
			try {
				assertThat(in.read()).isEqualTo(-1); // clean close by the server
			} catch (SocketTimeoutException notBounded) {
				throw new AssertionError("server did not bound a stalled TLS handshake", notBounded);
			} catch (IOException reset) {
				// connection reset by the server closing the stalled handshake — also bounded
				assertThat(reset).isNotNull();
			}
		}
	}

	private void assertConnectionRefused(SslContext ssl) {
		// Target an mTLS-required RPC (Renew): a bad client cert is refused either at
		// the
		// TLS layer (handshake fails -> UNAVAILABLE/INTERNAL/UNKNOWN) or, if the
		// OPTIONAL
		// toggle admits an unverified cert, by the interceptor's independent
		// re-validation
		// (-> UNAUTHENTICATED). Both are fail-closed; the RPC must never succeed.
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
					() -> GatewayIdentityGrpc.newBlockingStub(channel).renewGatewayIdentity(renewRequest()));
			assertThat(error).as("the RPC must fail closed").isNotNull();
			assertThat(error.getStatus().getCode()).isIn(Status.Code.UNAVAILABLE, Status.Code.INTERNAL,
					Status.Code.UNKNOWN, Status.Code.UNAUTHENTICATED);
		} finally {
			shutdown(channel);
		}
	}

	private RenewGatewayIdentityRequest renewRequest() {
		KeyPair keyPair = MtlsTestSupport.generateEcKeyPair();
		return RenewGatewayIdentityRequest.newBuilder()
				.setPkcs10Csr(ByteString.copyFrom(MtlsTestSupport.csr(keyPair, "probe-gateway")))
				.setCurrentGeneration(0).build();
	}

	private static ClientHello hello(int minMajor, int minMinor, int maxMajor, int maxMinor) {
		return ClientHello.newBuilder()
				.setClient(ComponentInfo.newBuilder().setName("SessionLayer Gateway").setSemver("0.1.0")
						.setProtocolMin(ProtocolVersions.of(minMajor, minMinor))
						.setProtocolMax(ProtocolVersions.of(maxMajor, maxMinor)).build())
				.build();
	}
}
