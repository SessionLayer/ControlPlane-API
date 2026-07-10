package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.ca.cert.CertificateProfiles;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.data.config.CaConfig;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import reactor.test.StepVerifier;

/**
 * CA lifecycle gates: fail-closed signing (FR-CA-9), a provisioned signer
 * produces a cryptographically-valid cert, rotation overlap-then-drain
 * (FR-CA-7) keeps the trusted set continuous (no fleet downtime), and a
 * backend/algorithm mismatch is rejected at validation (FR-CA-4). Own
 * container; cold start disabled so the test drives provisioning and rotation
 * explicitly.
 */
@Testcontainers
@SpringBootTest(properties = {"spring.grpc.server.port=0", "sessionlayer.coldstart.enabled=false"})
class CaLifecycleIT {

	@Container
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine")
			.withDatabaseName("sessionlayer").withUsername("sessionlayer").withPassword("sessionlayer");

	@DynamicPropertySource
	static void props(DynamicPropertyRegistry registry) {
		registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s", POSTGRES.getHost(),
				POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT), POSTGRES.getDatabaseName()));
		registry.add("spring.r2dbc.username", () -> "cp_runtime");
		registry.add("spring.r2dbc.password", () -> "cp_runtime");
		registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
		registry.add("spring.flyway.user", POSTGRES::getUsername);
		registry.add("spring.flyway.password", POSTGRES::getPassword);
		registry.add("spring.flyway.placeholders.cpRuntimePassword", () -> "cp_runtime");
	}

	@Autowired
	private CaProvisioningService provisioning;
	@Autowired
	private CaSignerService signerService;
	@Autowired
	private CaRotationService rotationService;
	@Autowired
	private io.sessionlayer.controlplane.data.config.CaConfigRepository caConfigs;
	@Autowired
	private io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository caKeyMaterials;

	private static ECPublicKey subjectKey() throws Exception {
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		return (ECPublicKey) g.generateKeyPair().getPublic();
	}

	@Test
	void activeSignerFailsClosedWithNoCa() {
		// Clean slate (this class's own container): no active session CA -> fail
		// closed.
		caKeyMaterials.deleteAll().then(caConfigs.deleteAll()).block(Duration.ofSeconds(10));
		StepVerifier.create(signerService.activeSigner("session")).verifyError(CaSignerService.NoSignerAvailable.class);
	}

	@Test
	void provisionedSignerProducesAVerifiableCert() throws Exception {
		provisioning.provisionAll().block(Duration.ofSeconds(20));
		SshCertSigner signer = signerService.activeSigner("session").block(Duration.ofSeconds(10));
		assertThat(signer).isNotNull();
		assertThat(signer.capabilities().supports("ecdsa-p256")).isTrue();

		var params = CertificateProfiles.innerLegSessionCert("sess-life", "alice@corp", "deploy", "10.0.0.0/8",
				Set.of("shell", "exec"), 5L, Instant.now());
		OpenSshCertificate cert = signer.signCertificate(new CertificateRequest(subjectKey(), params));

		ECPublicKey caPublicKey = SshEcdsaPublicKeys.parse(signer.caPublicKeyBlob());
		assertThat(CertTestSupport.verifyEcdsaCert(cert.blob(), caPublicKey)).isTrue();
		// the CA advertises a TrustedUserCAKeys line for the node fleet.
		assertThat(signer.caAuthorizedKey("session-ca")).startsWith("ecdsa-sha2-nistp256 ");
	}

	@Test
	void rotationOverlapThenDrainKeepsTrustContinuous() {
		provisioning.provisionAll().block(Duration.ofSeconds(20));
		// Steady state: one active session CA is trusted.
		assertThat(trusted()).hasSize(1);

		// Begin rotation: an incoming CA is pre-published -> both trusted (overlap
		// starts).
		rotationService.beginRotation("session", "session-ca-2").block(Duration.ofSeconds(10));
		assertThat(trusted()).hasSize(2);

		// Promote: old active -> outgoing, incoming -> active. Still both trusted (no
		// downtime).
		rotationService.promote("session").block(Duration.ofSeconds(10));
		assertThat(trusted()).hasSize(2);
		assertThat(activeName()).isEqualTo("session-ca-2"); // the new CA is now the signer

		// Drain: outgoing -> expired -> only the new CA remains trusted.
		rotationService.drain("session").block(Duration.ofSeconds(10));
		assertThat(trusted()).hasSize(1);
	}

	@Test
	void backendAlgorithmMismatchRejectedAtValidation() {
		// ed25519 is not producible by our ECDSA assembler -> rejected at validation.
		CaConfig ed = new CaConfig(io.sessionlayer.controlplane.data.Uuids.v7(), "bad-ed25519", "user", "local",
				"local:x", "ed25519", "active", "default", null, null, null);
		StepVerifier.create(signerService.signerFor(ed)).verifyError(CaBackendCapabilities.AlgorithmNotSupported.class);
	}

	@Autowired
	private org.springframework.r2dbc.core.DatabaseClient db;

	private List<String> trusted() {
		return rotationService.trustedCaKeys("session").block(Duration.ofSeconds(10));
	}

	private String activeName() {
		return db.sql("SELECT name FROM config.ca_config WHERE ca_kind = 'session' AND rotation_state = 'active'")
				.map(row -> row.get(0, String.class)).one().block();
	}
}
