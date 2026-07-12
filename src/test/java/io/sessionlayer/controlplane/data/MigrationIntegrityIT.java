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
		// V1..V20. S4 adds V14/V15; S6 adds V16 (auth surface); S9 adds V17 (recording:
		// customer-key config on operator_settings + the recording_token table); S10
		// adds V18 (widen platform_role.permissions CHECK for lock:read/lock:write — no
		// table); S12 adds V19 (agent_identity.prev_fingerprint — the renew-ahead
		// fingerprint-pin overlap column, mirroring V15's gateway pinning — no table);
		// S13 adds V20 (access models: the 3 break-glass stores + the activation
		// enrichment columns + the breakglass:manage permission).
		assertThat(maxVersion).isEqualTo(20);

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
		// 22 (9 config + 13 runtime); S3 adds 8 -> 30; S4 (V14) adds 2 -> 32; S6 (V16)
		// adds 3 runtime -> 35; S9 (V17) adds 1 runtime (recording_token) -> 36; S13
		// (V20) adds 3 runtime (breakglass_credential, breakglass_offline_code,
		// breakglass_token) -> 39 (12 config + 27 runtime). A drop fails it.
		Long tables = db
				.sql("SELECT count(*) AS c FROM information_schema.tables "
						+ "WHERE table_schema IN ('config','runtime') AND table_type = 'BASE TABLE' "
						+ "AND NOT (table_schema = 'runtime' AND table_name LIKE 'audit\\_event\\_%')")
				.map(row -> row.get("c", Long.class)).one().block();
		assertThat(tables).isEqualTo(39L); // 12 config + 27 runtime

		// spot-check the reserved-name renames and the load-bearing tables actually
		// landed
		for (String qualified : new String[]{"runtime.ssh_session", "runtime.access_lock", "runtime.audit_event",
				"runtime.recording_ref", "runtime.recording_token", "runtime.presence", "config.dp_rule",
				"config.ca_config", "runtime.breakglass_credential", "runtime.breakglass_offline_code",
				"runtime.breakglass_token", "runtime.jit_request", "runtime.breakglass_activation"}) {
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
	void recordingCustomerKeyAndTokenSchemaLanded() {
		// V17: operator_settings gains the customer-key config, and recording_token
		// (the single-use BeginRecording authority) exists with its binding columns.
		for (String column : new String[]{"recording_customer_public_key", "recording_key_seal_algorithm",
				"recording_key_ref", "recording_retention_days", "recording_strict_default"}) {
			Long found = db.sql("SELECT count(*) AS c FROM information_schema.columns "
					+ "WHERE table_schema = 'config' AND table_name = 'operator_settings' AND column_name = :col")
					.bind("col", column).map(row -> row.get("c", Long.class)).one().block();
			assertThat(found).as("operator_settings.%s exists", column).isEqualTo(1L);
		}
		for (String column : new String[]{"token_hash", "gateway_id", "session_id", "node_id", "principal", "used"}) {
			Long found = db.sql("SELECT count(*) AS c FROM information_schema.columns "
					+ "WHERE table_schema = 'runtime' AND table_name = 'recording_token' AND column_name = :col")
					.bind("col", column).map(row -> row.get("c", Long.class)).one().block();
			assertThat(found).as("recording_token.%s exists", column).isEqualTo(1L);
		}
	}

	@Test
	void secondMigrateIsANoOp() {
		// Idempotency: re-running Flyway against the already-migrated DB executes
		// nothing.
		var result = flyway.migrate();
		assertThat(result.migrationsExecuted).isZero();
	}
}
