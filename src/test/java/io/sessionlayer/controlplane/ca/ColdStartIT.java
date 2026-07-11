package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import reactor.core.publisher.Flux;

/**
 * Dedicated gate for cold-start CA provisioning (FR-BOOT-1 / D31, §5.5). Boots
 * the full context against a fresh empty DB with cold start <b>enabled</b> (the
 * production default), and proves: the three CAs (session/user/host) + the
 * operator-settings singleton are provisioned exactly once at startup; a re-run
 * is a no-op (idempotent, restart-safe); and two concurrent provisions against
 * an empty DB produce exactly one CA set (race-safe — advisory lock + unique
 * index).
 */
@Testcontainers
@SpringBootTest(properties = {"spring.grpc.server.port=0"})
class ColdStartIT {

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
		registry.add("sessionlayer.ca.local.allow-dev-kek", () -> "true");
		// Bind the mTLS gRPC server to an ephemeral port so this context does not clash
		// with another cached test context on :9090 (cold start now also provisions the
		// internal mTLS CA, which this IT's assertions tolerate via >= counts).
		registry.add("sessionlayer.mtls.server.port", () -> "0");
		// cold start left at its default (enabled) — this IT proves it.
	}

	@Autowired
	private CaProvisioningService provisioning;
	@Autowired
	private CaConfigRepository caConfigs;
	@Autowired
	private OperatorSettingsRepository operatorSettings;
	@Autowired
	private CaKeyMaterialRepository caKeyMaterials;
	@Autowired
	private DatabaseClient db;

	private long activeCount() {
		return db.sql("SELECT count(*) FROM config.ca_config WHERE rotation_state = 'active'")
				.map(row -> row.get(0, Long.class)).one().block();
	}

	private long activeCount(String kind) {
		return db.sql("SELECT count(*) FROM config.ca_config WHERE rotation_state = 'active' AND ca_kind = :k")
				.bind("k", kind).map(row -> row.get(0, Long.class)).one().block();
	}

	@Test
	void startupProvisionedTheThreeCasAndSettings() {
		assertThat(operatorSettings.findSingleton().block()).isNotNull();
		assertThat(activeCount("session")).isEqualTo(1);
		assertThat(activeCount("user")).isEqualTo(1);
		assertThat(activeCount("host")).isEqualTo(1);
		// each local CA has KEK-wrapped material persisted.
		assertThat(caKeyMaterials.count().block()).isGreaterThanOrEqualTo(3L);
	}

	@Test
	void reProvisioningIsIdempotent() {
		long before = activeCount();
		provisioning.provisionAll().block(Duration.ofSeconds(20));
		assertThat(activeCount()).isEqualTo(before); // no new CAs on a re-run
	}

	@Test
	void concurrentProvisioningIsRaceSafe() {
		// Clean slate, then two concurrent provisions must still yield exactly one CA
		// set.
		// ca_key_material is INSERT/SELECT-only for the runtime role, so clean up as
		// owner.
		OwnerDb.of(POSTGRES).sql("DELETE FROM runtime.ca_key_material").then()
				.then(OwnerDb.of(POSTGRES).sql("DELETE FROM config.ca_config").then()).block();
		assertThat(activeCount()).isZero();

		Flux.merge(provisioning.provisionAll(), provisioning.provisionAll()).blockLast(Duration.ofSeconds(30));

		assertThat(activeCount("session")).isEqualTo(1);
		assertThat(activeCount("user")).isEqualTo(1);
		assertThat(activeCount("host")).isEqualTo(1);
	}
}
