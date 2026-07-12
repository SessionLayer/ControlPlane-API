package io.sessionlayer.controlplane;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Integration smoke: boots the full Spring context against a REAL Postgres
 * (Testcontainers), proving the production wiring end to end — Flyway
 * migrations run over JDBC, the runtime connects over R2DBC, and the
 * contract-first probes serve. Runs in the {@code verify} phase (Failsafe,
 * {@code
 * *IT}); needs Docker.
 *
 * <p>
 * Both the R2DBC runtime datasource and the separate JDBC Flyway datasource are
 * pointed at the one container via {@link DynamicPropertySource}, which
 * demonstrates (and asserts) the intentional R2DBC-runtime / JDBC-Flyway split.
 */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		// Ephemeral mTLS gRPC port: the full production boot (incl. the mTLS server) is
		// exercised, but on an OS-assigned port so cached test contexts never clash on
		// :9090. The WORM health contributor is disabled here (no MinIO in this smoke
		// context) so the root /actuator/health reflects the real Postgres wiring, not
		// an
		// (expected) unreachable store; the indicator's verdict is unit-tested
		// (WormHealthIndicatorTest) and the readiness opt-in in WormReadinessIncludeIT.
		properties = {"sessionlayer.mtls.server.port=0", "management.health.worm.enabled=false"})
class ControlPlaneSmokeIT {

	@Container
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine")
			.withDatabaseName("sessionlayer").withUsername("sessionlayer").withPassword("sessionlayer");

	@DynamicPropertySource
	static void dataSources(DynamicPropertyRegistry registry) {
		// Runtime = R2DBC (fully non-blocking) as the RESTRICTED cp_runtime role — the
		// production posture (writer-role hardening, F-append-only-1). The full app
		// must
		// boot and serve under least privilege.
		registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s", POSTGRES.getHost(),
				POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT), POSTGRES.getDatabaseName()));
		registry.add("spring.r2dbc.username", () -> "cp_runtime");
		registry.add("spring.r2dbc.password", () -> "cp_runtime");
		// Migrations = Flyway (JDBC-only) as the OWNER, same container.
		registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
		registry.add("spring.flyway.user", POSTGRES::getUsername);
		registry.add("spring.flyway.password", POSTGRES::getPassword);
		registry.add("spring.flyway.placeholders.cpRuntimePassword", () -> "cp_runtime");
		registry.add("sessionlayer.ca.local.allow-dev-kek", () -> "true");
	}

	private WebTestClient webTestClient;

	@Value("${local.server.port}")
	private int port;

	@BeforeEach
	void bindClient() {
		webTestClient = WebTestClient.bindToServer().baseUrl("http://localhost:" + port).build();
	}

	@Test
	void healthzIsPass() {
		webTestClient.get().uri("/v1/healthz").exchange().expectStatus().isOk().expectBody().jsonPath("$.status")
				.isEqualTo("pass");
	}

	@Test
	void actuatorHealthIsUpAgainstRealPostgres() {
		webTestClient.get().uri("/actuator/health").exchange().expectStatus().isOk().expectBody().jsonPath("$.status")
				.isEqualTo("UP");
	}

	@Test
	void versionAdvertisesProtocolRange() {
		webTestClient.get().uri("/v1/version").exchange().expectStatus().isOk().expectBody().jsonPath("$.component")
				.isEqualTo("SessionLayer Control Plane").jsonPath("$.version").isEqualTo("0.1.0")
				.jsonPath("$.protocols.controlPlaneGatewayGrpc.min").isEqualTo("1.0")
				.jsonPath("$.protocols.controlPlaneGatewayGrpc.max").isEqualTo("1.1");
	}

	@Test
	void flywayBaselineMigrationApplied() throws Exception {
		try (Connection connection = POSTGRES.createConnection("");
				Statement statement = connection.createStatement();
				ResultSet rs = statement
						.executeQuery("SELECT COUNT(*) FROM flyway_schema_history WHERE success = true")) {
			assertThat(rs.next()).isTrue();
			assertThat(rs.getInt(1)).isGreaterThanOrEqualTo(1);
		}
	}
}
