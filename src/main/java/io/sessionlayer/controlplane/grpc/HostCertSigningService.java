package io.sessionlayer.controlplane.grpc;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.gateway.GatewayHostCertificateService;
import io.sessionlayer.controlplane.gateway.IssuedHostCertificate;
import io.sessionlayer.controlplane.grpc.v1.HostCertSigningGrpc;
import io.sessionlayer.controlplane.grpc.v1.SignGatewayHostCertificateRequest;
import io.sessionlayer.controlplane.grpc.v1.SignGatewayHostCertificateResponse;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * gRPC server for {@code HostCertSigning} (S16, Design §9.3/§11): signs the
 * Gateway's OUTER host certificate for the ProxyJump host-cert MITM path and
 * returns the <b>certificate only</b>. mTLS-required tier — the
 * {@link AuthInterceptor} resolves the caller; this RPC is NOT session-bound,
 * so the caller's Gateway mTLS identity (active + unlocked) is the sole
 * authority. A null/agent/locked/revoked peer is refused with a generic error
 * by the service.
 */
@Service
public class HostCertSigningService extends HostCertSigningGrpc.HostCertSigningImplBase {

	private final GatewayHostCertificateService signing;
	private final MtlsProperties properties;

	public HostCertSigningService(GatewayHostCertificateService signing, MtlsProperties properties) {
		this.signing = signing;
		this.properties = properties;
	}

	@Override
	public void signGatewayHostCertificate(SignGatewayHostCertificateRequest request,
			StreamObserver<SignGatewayHostCertificateResponse> observer) {
		MtlsPeer peer = MtlsContext.peer();
		// gatewayId() is null for an Agent peer (cross-namespace) — the service treats
		// that as unauthenticated (a host cert is a Gateway-only credential).
		Mono<SignGatewayHostCertificateResponse> result = signing
				.sign(peer.gatewayId(), request.getHostPublicKey().toByteArray(), request.getHostPrincipalsList())
				.map(HostCertSigningService::toResponse);
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "SignGatewayHostCertificate");
	}

	private static SignGatewayHostCertificateResponse toResponse(IssuedHostCertificate cert) {
		return SignGatewayHostCertificateResponse.newBuilder().setCertificateLine(cert.certificateLine())
				.setCertificateBlob(ByteString.copyFrom(cert.certificateBlob()))
				.setValidAfterEpochSeconds(cert.validAfterEpochSeconds())
				.setValidBeforeEpochSeconds(cert.validBeforeEpochSeconds()).build();
	}
}
