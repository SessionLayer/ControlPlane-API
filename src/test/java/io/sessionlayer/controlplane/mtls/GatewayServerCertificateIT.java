package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.grpc.v1.GatewayIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.IssueGatewayServerCertificateRequest;
import io.sessionlayer.controlplane.grpc.v1.IssueGatewayServerCertificateResponse;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * S14 — {@code IssueGatewayServerCertificate}: the serverAuth leaf for a
 * Gateway's agent-facing TLS listener. mTLS is REQUIRED; the CP (never the
 * caller) chooses the SANs; a locked/inactive identity is refused — which is
 * exactly how this credential is revoked, since it carries no generation
 * counter.
 */
class GatewayServerCertificateIT extends AbstractMtlsIT {

	private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
	private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

	@Test
	void issuesAServerAuthLeafWithCpChosenSansIgnoringAHostileCsr() throws Exception {
		String name = "gw-servercert-" + unique();
		EnrolledGateway gateway = enroll(name);

		// A SEPARATE keypair for the TLS server (key separation from the identity), and
		// a hostile CSR: it claims another gateway's name as its subject AND requests
		// SANs for a name it does not own. Neither may reach the issued certificate.
		KeyPair serverKey = MtlsTestSupport.generateEcKeyPair();
		byte[] hostileCsr = MtlsTestSupport.csrRequestingSans(serverKey, "victim-gateway",
				List.of("victim-gateway", "evil.example.com"));

		IssueGatewayServerCertificateResponse response = issueServerCert(gateway, hostileCsr);

		X509Certificate leaf = X509Certificates.parse(response.getCertificate().toByteArray());

		// serverAuth, and ONLY serverAuth — an Agent validating this as a server cert
		// accepts it, where the Gateway's clientAuth identity leaf would be rejected.
		assertThat(leaf.getExtendedKeyUsage()).containsExactly(SERVER_AUTH);
		assertThat(leaf.getExtendedKeyUsage()).doesNotContain(CLIENT_AUTH);

		// The CP stamped its OWN names, from the gateway_identity row it holds. The
		// caller's requested subject/SANs were discarded, not honoured.
		assertThat(leaf.getSubjectX500Principal().getName()).isEqualTo("CN=" + name);
		assertThat(dnsSans(leaf)).containsExactly(name);
		assertThat(dnsSans(leaf)).doesNotContain("victim-gateway", "evil.example.com");
		assertThat(uriSans(leaf)).containsExactly(GatewayIdentityUri.of(gateway.gatewayId()));
		assertThat(response.getGatewayName()).isEqualTo(name);

		// It certifies the SERVER keypair the caller generated — not the identity key.
		assertThat(leaf.getPublicKey()).isEqualTo(serverKey.getPublic());
		assertThat(leaf.getPublicKey()).isNotEqualTo(gateway.certificate().getPublicKey());

		// Validity is backdated for skew and bounded by the identity cert TTL.
		assertThat(response.getNotBeforeEpochSeconds()).isLessThan(Instant.now().getEpochSecond());
		assertThat(response.getNotAfterEpochSeconds()).isGreaterThan(Instant.now().getEpochSecond());

		Long audited = db
				.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'gateway.server_cert.issue' "
						+ "AND outcome = 'success' AND actor = :actor")
				.bind("actor", name).map(row -> row.get(0, Long.class)).one().block();
		assertThat(audited).isEqualTo(1L);
	}

	@Test
	void issuedLeafChainsToTheInternalMtlsCa() throws Exception {
		EnrolledGateway gateway = enroll("gw-servercert-chain-" + unique());
		KeyPair serverKey = MtlsTestSupport.generateEcKeyPair();

		IssueGatewayServerCertificateResponse response = issueServerCert(gateway,
				MtlsTestSupport.csr(serverKey, "tls-server"));

		X509Certificate leaf = X509Certificates.parse(response.getCertificate().toByteArray());
		assertThat(response.getCaChainList()).hasSize(1);
		assertThat(X509Certificates.parse(response.getCaChain(0).toByteArray())).isEqualTo(caCertificate());

		// The Agent's check: a PKIX path from the presented leaf to the internal mTLS
		// CA it already holds — no trust on first use.
		CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(List.of(leaf));
		PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(caCertificate(), null)));
		params.setRevocationEnabled(false);
		assertThatCode(() -> CertPathValidator.getInstance("PKIX").validate(path, params)).doesNotThrowAnyException();
	}

	@Test
	void refusesACallerWithNoClientCertificate() {
		KeyPair serverKey = MtlsTestSupport.generateEcKeyPair();
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(),
				MtlsTestSupport.clientSslContext(caCertificate(), null, null));
		try {
			StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
					() -> GatewayIdentityGrpc.newBlockingStub(channel)
							.issueGatewayServerCertificate(request(MtlsTestSupport.csr(serverKey, "tls-server"))));

			// Not a bootstrap-tier RPC: the interceptor refuses it before the handler.
			assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
		} finally {
			shutdown(channel);
		}
	}

	@Test
	void refusesALockedGatewayIdentity() {
		String name = "gw-servercert-locked-" + unique();
		EnrolledGateway gateway = enroll(name);
		lockIdentity(gateway, "locked");

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> issueServerCert(gateway, MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "tls-server")));

		// This IS the revocation path for the server cert: no reissue, and the
		// outstanding leaf simply expires (there is no generation counter to bump).
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
		assertThat(deniedIssuances(name)).isEqualTo(1L);
	}

	@Test
	void refusesARevokedGatewayIdentity() {
		String name = "gw-servercert-revoked-" + unique();
		EnrolledGateway gateway = enroll(name);
		lockIdentity(gateway, "revoked");

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> issueServerCert(gateway, MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "tls-server")));

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
		assertThat(deniedIssuances(name)).isEqualTo(1L);
	}

	@Test
	void refusesAValidCertificateForAnUnknownGatewayIdentity() {
		// A genuinely CA-signed client cert whose SAN names a gateway_identity that
		// does not exist (never enrolled / deleted). The lookup must fail closed.
		KeyPair key = MtlsTestSupport.generateEcKeyPair();
		X509Certificate stranger = mintClientCert(key.getPublic(), UUID.randomUUID(), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(3600));

		StatusRuntimeException error = callWithClientCert(stranger, key);

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void refusesAnAgentPeerHoldingAValidAgentCertificate() {
		// Cross-namespace: an Agent is a valid mTLS peer on this plane (S12) but it is
		// not a Gateway — it must not be able to obtain a Gateway server certificate.
		KeyPair key = MtlsTestSupport.generateEcKeyPair();
		X509Certificate agentLeaf = mintAgentClientCert(key.getPublic(), UUID.randomUUID());

		StatusRuntimeException error = callWithClientCert(agentLeaf, key);

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void refusesAnUnverifiableCsr() {
		EnrolledGateway gateway = enroll("gw-servercert-badcsr-" + unique());

		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> issueServerCert(gateway, new byte[]{1, 2, 3, 4}));

		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.INVALID_ARGUMENT);
	}

	private void lockIdentity(EnrolledGateway gateway, String status) {
		db.sql("UPDATE runtime.gateway_identity SET status = :status WHERE id = :id").bind("status", status)
				.bind("id", gateway.gatewayId()).fetch().rowsUpdated().block();
	}

	private Long deniedIssuances(String name) {
		return db
				.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'gateway.server_cert.issue' "
						+ "AND outcome = 'denied' AND actor = :actor")
				.bind("actor", name).map(row -> row.get(0, Long.class)).one().block();
	}

	/** An AGENT-namespace client leaf, signed by the same internal CA (S12). */
	private X509Certificate mintAgentClientCert(PublicKey publicKey, UUID agentId) {
		return mtlsCa.activeBackend().block()
				.issueLeaf(new LeafCertificateSpec(publicKey, "probe-agent", List.of("probe-agent"),
						List.of(AgentIdentityUri.of(agentId)), LeafPurpose.CLIENT,
						BigInteger.valueOf(System.nanoTime()), Instant.now().minusSeconds(60),
						Instant.now().plusSeconds(3600)));
	}

	private StatusRuntimeException callWithClientCert(X509Certificate leaf, KeyPair key) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), leaf, key.getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), "tls-server");
			return catchThrowableOfType(StatusRuntimeException.class,
					() -> GatewayIdentityGrpc.newBlockingStub(channel).issueGatewayServerCertificate(request(csr)));
		} finally {
			shutdown(channel);
		}
	}

	private IssueGatewayServerCertificateResponse issueServerCert(EnrolledGateway gateway, byte[] csr) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return GatewayIdentityGrpc.newBlockingStub(channel).issueGatewayServerCertificate(request(csr));
		} finally {
			shutdown(channel);
		}
	}

	private static IssueGatewayServerCertificateRequest request(byte[] csr) {
		return IssueGatewayServerCertificateRequest.newBuilder().setPkcs10Csr(ByteString.copyFrom(csr)).build();
	}

	private static List<String> dnsSans(X509Certificate leaf) throws Exception {
		return sanValues(leaf.getSubjectAlternativeNames(), 2);
	}

	private static List<String> uriSans(X509Certificate leaf) throws Exception {
		return sanValues(leaf.getSubjectAlternativeNames(), 6);
	}

	private static List<String> sanValues(Collection<List<?>> sans, int generalNameType) {
		return sans.stream().filter(san -> ((Integer) san.get(0)) == generalNameType).map(san -> (String) san.get(1))
				.toList();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
