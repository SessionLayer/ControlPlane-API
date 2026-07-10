package io.sessionlayer.controlplane.data;

import io.r2dbc.spi.ConnectionFactories;
import io.r2dbc.spi.ConnectionFactoryOptions;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Base for the data-model integration tests. Boots the full Spring context (so
 * the real R2DBC wiring, converters, auditing and naming strategy are
 * exercised) against a <b>singleton</b> Testcontainers Postgres shared across
 * every subclass — one container start and one cached context for the whole
 * {@code *IT} suite, which keeps CI fast. Flyway (JDBC) migrates the schema at
 * startup; the runtime talks R2DBC. Needs Docker; runs in the {@code verify}
 * phase (Failsafe).
 */
@SpringBootTest(properties = "spring.grpc.server.port=0")
abstract class AbstractDataIT {

	@SuppressWarnings("resource") // shared singleton; stopped by Ryuk at JVM exit, not per-class
	static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine")
			.withDatabaseName("sessionlayer").withUsername("sessionlayer").withPassword("sessionlayer");

	static {
		POSTGRES.start();
	}

	/**
	 * A DatabaseClient connecting as the OWNER/superuser — for maintenance
	 * operations that the restricted runtime role is (correctly) not allowed to
	 * perform: the append-only trigger proof, partition prune (audit erase is
	 * owner-only), and crown-jewel cleanup.
	 */
	static DatabaseClient ownerClient() {
		return DatabaseClient.create(ConnectionFactories.get(ConnectionFactoryOptions.builder()
				.option(ConnectionFactoryOptions.DRIVER, "postgresql")
				.option(ConnectionFactoryOptions.HOST, POSTGRES.getHost())
				.option(ConnectionFactoryOptions.PORT, POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT))
				.option(ConnectionFactoryOptions.DATABASE, POSTGRES.getDatabaseName())
				.option(ConnectionFactoryOptions.USER, POSTGRES.getUsername())
				.option(ConnectionFactoryOptions.PASSWORD, POSTGRES.getPassword()).build()));
	}

	/**
	 * The restricted runtime role created by migration V11 (writer-role hardening).
	 */
	static final String RUNTIME_ROLE = "cp_runtime";
	static final String RUNTIME_PASSWORD = "cp_runtime";

	@DynamicPropertySource
	static void dataSources(DynamicPropertyRegistry registry) {
		// Migrations = Flyway (JDBC) as the OWNER/superuser (creates the cp_runtime
		// role
		// in V11). Runtime = R2DBC (non-blocking) as the RESTRICTED cp_runtime role, so
		// the entire IT suite exercises the least-privilege writer-role end to end
		// (F-append-only-1). Same container.
		registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s", POSTGRES.getHost(),
				POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT), POSTGRES.getDatabaseName()));
		registry.add("spring.r2dbc.username", () -> RUNTIME_ROLE);
		registry.add("spring.r2dbc.password", () -> RUNTIME_PASSWORD);
		registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
		registry.add("spring.flyway.user", POSTGRES::getUsername);
		registry.add("spring.flyway.password", POSTGRES::getPassword);
		registry.add("spring.flyway.placeholders.cpRuntimePassword", () -> RUNTIME_PASSWORD);
		// Cold-start CA provisioning is proven in its own ColdStartIT; disable it here
		// so
		// these shared-context CRUD/constraint fixtures own their ca_config rows
		// without
		// colliding with the seeded active-per-kind CAs.
		registry.add("sessionlayer.coldstart.enabled", () -> "false");
		// The dev-default KEK is fine for tests (fail-closed opt-in); partition
		// create-ahead
		// is proven in AuditPartitioningIT, so keep this fast suite lean.
		registry.add("sessionlayer.ca.local.allow-dev-kek", () -> "true");
		registry.add("sessionlayer.audit.partition-maintenance.enabled", () -> "false");
	}
}
