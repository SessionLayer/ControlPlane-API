package io.sessionlayer.controlplane.data;

import org.springframework.boot.test.context.SpringBootTest;
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

	@DynamicPropertySource
	static void dataSources(DynamicPropertyRegistry registry) {
		// Runtime = R2DBC (non-blocking); migrations = Flyway (JDBC). Same container.
		registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s", POSTGRES.getHost(),
				POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT), POSTGRES.getDatabaseName()));
		registry.add("spring.r2dbc.username", POSTGRES::getUsername);
		registry.add("spring.r2dbc.password", POSTGRES::getPassword);
		registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
		registry.add("spring.flyway.user", POSTGRES::getUsername);
		registry.add("spring.flyway.password", POSTGRES::getPassword);
	}
}
