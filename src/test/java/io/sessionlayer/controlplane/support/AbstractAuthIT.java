package io.sessionlayer.controlplane.support;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Base for the Session Six authentication ITs. Boots the full Spring context
 * (real R2DBC wiring + the auth services) against a <b>singleton</b>
 * Testcontainers Postgres shared across subclasses. Runtime connects as the
 * restricted {@code cp_runtime} role; Flyway migrates (incl. V16) as the owner.
 * The mTLS gRPC server and CA cold start are disabled (these ITs neither need
 * them nor the internal CA); the OIDC RP is off by default (subclasses that
 * need the {@code oidc-mock} enable it).
 */
// Raise the token-endpoint rate limit for ITs: all suites share the localhost
// source bucket, so the fixed-window default (30/min) is exhausted cumulatively
// by
// the CRUD suites in a fast CI run, flaking later suites with `rate_limited`.
// Tests
// exercise the limiter directly in AuthController/OtpService tests, not here.
@SpringBootTest(properties = {"sessionlayer.mtls.server.port=0", "sessionlayer.auth.token-endpoint.max=1000000"})
public abstract class AbstractAuthIT {

	@SuppressWarnings("resource")
	protected static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17-alpine")
			.withDatabaseName("sessionlayer").withUsername("sessionlayer").withPassword("sessionlayer");

	static {
		POSTGRES.start();
	}

	@DynamicPropertySource
	static void properties(DynamicPropertyRegistry registry) {
		registry.add("spring.r2dbc.url", () -> String.format("r2dbc:postgresql://%s:%d/%s", POSTGRES.getHost(),
				POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT), POSTGRES.getDatabaseName()));
		registry.add("spring.r2dbc.username", () -> "cp_runtime");
		registry.add("spring.r2dbc.password", () -> "cp_runtime");
		registry.add("spring.flyway.url", POSTGRES::getJdbcUrl);
		registry.add("spring.flyway.user", POSTGRES::getUsername);
		registry.add("spring.flyway.password", POSTGRES::getPassword);
		registry.add("spring.flyway.placeholders.cpRuntimePassword", () -> "cp_runtime");
		registry.add("sessionlayer.coldstart.enabled", () -> "false");
		registry.add("sessionlayer.mtls.server.enabled", () -> "false");
		registry.add("sessionlayer.ca.local.allow-dev-kek", () -> "true");
	}
}
