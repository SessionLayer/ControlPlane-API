package io.sessionlayer.controlplane;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;

/**
 * SessionLayer Control Plane entry point.
 *
 * <p>
 * {@link DataSourceAutoConfiguration} is excluded on purpose: the application
 * runtime accesses Postgres exclusively over R2DBC (fully non-blocking), so
 * there must be no primary blocking JDBC {@code DataSource} on the request
 * path. Flyway still gets its own dedicated JDBC datasource built from
 * {@code spring.flyway.*} at startup (Flyway is JDBC-only). This is the
 * intentional R2DBC-runtime / JDBC-Flyway split documented in CLAUDE.md — not
 * an oversight.
 */
@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
public class ControlplaneApplication {

	public static void main(String[] args) {
		SpringApplication.run(ControlplaneApplication.class, args);
	}
}
