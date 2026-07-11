package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

/**
 * Migration integrity + schema-shape (§8.1, §8.2): all Flyway migrations apply
 * on a fresh Postgres and reach the latest version; both schemas and every §12A
 * table exist; config {@code origin} defaults to {@code 'default'}; a second
 * migrate is a no-op.
 */
class MigrationIntegrityIT extends AbstractDataIT {

	@Autowired
	private DatabaseClient db;

	@Autowired
	private Flyway flyway;

	@Test
	void allMigrationsAppliedThroughLatest() {
		Integer maxVersion = db.sql("SELECT max(version::int) AS v FROM flyway_schema_history WHERE success = true")
				.map(row -> row.get("v", Integer.class)).one().block();
		assertThat(maxVersion).isEqualTo(14); // V1..V14 (S4 adds V14: mTLS CA + tokens)

		Long failed = db.sql("SELECT count(*) AS c FROM flyway_schema_history WHERE success = false")
				.map(row -> row.get("c", Long.class)).one().block();
		assertThat(failed).isZero();
	}

	@Test
	void bothSchemasExist() {
		Long schemas = db
				.sql("SELECT count(*) AS c FROM information_schema.schemata "
						+ "WHERE schema_name IN ('config','runtime')")
				.map(row -> row.get("c", Long.class)).one().block();
		assertThat(schemas).isEqualTo(2);
	}

	@Test
	void allBaseEntityTablesExist() {
		// Top-level entity tables (excludes the audit_event range partitions). S2 had
		// 22 (9 config + 13 runtime); S3 adds 8 -> 30 (12 config + 18 runtime); S4
		// (V14)
		// adds 2 runtime (gateway_enrollment_token, session_signing_token) -> 32
		// (12 config + 20 runtime). A drop fails it.
		Long tables = db
				.sql("SELECT count(*) AS c FROM information_schema.tables "
						+ "WHERE table_schema IN ('config','runtime') AND table_type = 'BASE TABLE' "
						+ "AND NOT (table_schema = 'runtime' AND table_name LIKE 'audit\\_event\\_%')")
				.map(row -> row.get("c", Long.class)).one().block();
		assertThat(tables).isEqualTo(32L); // 12 config + 20 runtime

		// spot-check the reserved-name renames and the load-bearing tables actually
		// landed
		for (String qualified : new String[]{"runtime.ssh_session", "runtime.access_lock", "runtime.audit_event",
				"runtime.recording_ref", "runtime.presence", "config.dp_rule", "config.ca_config"}) {
			String[] parts = qualified.split("\\.");
			Long found = db
					.sql("SELECT count(*) AS c FROM information_schema.tables "
							+ "WHERE table_schema = :s AND table_name = :t")
					.bind("s", parts[0]).bind("t", parts[1]).map(row -> row.get("c", Long.class)).one().block();
			assertThat(found).as("table %s exists", qualified).isEqualTo(1L);
		}
	}

	@Test
	void configOriginDefaultsToDefault() {
		UUID id = Uuids.v7();
		db.sql("INSERT INTO config.capability_def (id, name) VALUES (:id, 'exec')").bind("id", id).fetch().rowsUpdated()
				.block();
		String origin = db.sql("SELECT origin FROM config.capability_def WHERE id = :id").bind("id", id)
				.map(row -> row.get("origin", String.class)).one().block();
		assertThat(origin).isEqualTo("default");
	}

	@Test
	void runtimeTablesHaveNoOriginColumn() {
		// The config-vs-runtime boundary is structural: runtime rows are never
		// reconciled,
		// so they carry no `origin` (FR-DATA-1 / FR-API-3).
		Long withOrigin = db
				.sql("SELECT count(*) AS c FROM information_schema.columns "
						+ "WHERE table_schema = 'runtime' AND column_name = 'origin'")
				.map(row -> row.get("c", Long.class)).one().block();
		assertThat(withOrigin).isZero();
	}

	@Test
	void secondMigrateIsANoOp() {
		// Idempotency: re-running Flyway against the already-migrated DB executes
		// nothing.
		var result = flyway.migrate();
		assertThat(result.migrationsExecuted).isZero();
	}
}
