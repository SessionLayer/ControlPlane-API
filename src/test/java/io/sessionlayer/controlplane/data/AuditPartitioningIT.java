package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;

/**
 * Dedicated gate for §6.1 — audit_event range partitioning + FR-AUD-6
 * retention. Proves rows route to the correct monthly partitions; that pruning
 * DETACH+DROPs whole partitions entirely older than the cutoff while in-window
 * rows survive; that {@code findById}, insert and the append-only trigger still
 * work on the partitioned table; and that a legal-hold / compliance recording
 * is never returned as prunable (the "legal_hold row is not pruned" assertion).
 *
 * <p>
 * Runs as the restricted {@code cp_runtime} role (AbstractDataIT): it may
 * EXECUTE the create-ahead {@code audit_ensure_partition}, but retention (the
 * partition DROP in {@code audit_prune_before}) is owner-only, so prune here
 * runs via an owner connection (F-audit-role-bypass-1).
 */
class AuditPartitioningIT extends AbstractDataIT {

	@Autowired
	private AuditEventRepository audits;

	@Autowired
	private RecordingRefRepository recordings;

	@Autowired
	private SshSessionRepository sessions;

	@Autowired
	private DatabaseClient db;

	private static Instant midMonth(int monthsFromNow) {
		return YearMonth.now(ZoneOffset.UTC).plusMonths(monthsFromNow).atDay(15).atStartOfDay(ZoneOffset.UTC)
				.toInstant();
	}

	private static String partitionOf(int monthsFromNow) {
		return "audit_event_" + YearMonth.now(ZoneOffset.UTC).plusMonths(monthsFromNow)
				.format(java.time.format.DateTimeFormatter.ofPattern("yyyyMM"));
	}

	private String partitionForRow(UUID id) {
		return db.sql("SELECT tableoid::regclass::text FROM runtime.audit_event WHERE id = :id").bind("id", id)
				.map(row -> row.get(0, String.class)).one().block();
	}

	private long partitionCount(String name) {
		return db.sql(
				"SELECT count(*) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid " + "WHERE c.relname = :n")
				.bind("n", name).map(row -> row.get(0, Long.class)).one().block();
	}

	private AuditEvent auditAt(Instant when, String actor) {
		return AuditEvent.create(when, actor, null, "probe", "success", null, null, null, null, null, null, null, null);
	}

	/**
	 * Ensure the monthly partition for {@code monthsFromNow} exists. Makes each
	 * test order-independent: another test's prune may have dropped a seeded
	 * partition, so a test re-creates exactly the partitions it needs before
	 * inserting.
	 */
	private void ensure(int monthsFromNow) {
		java.time.LocalDate d = YearMonth.now(ZoneOffset.UTC).plusMonths(monthsFromNow).atDay(1);
		db.sql("SELECT runtime.audit_ensure_partition(:d)").bind("d", d).fetch().one().block();
	}

	@Test
	void rowsRouteToCorrectMonthlyPartitions() {
		ensure(-5);
		ensure(0);
		ensure(2);
		var past = audits.save(auditAt(midMonth(-5), "past")).block();
		var now = audits.save(auditAt(midMonth(0), "now")).block();
		var future = audits.save(auditAt(midMonth(2), "future")).block();

		assertThat(partitionForRow(past.id())).isEqualTo("runtime." + partitionOf(-5));
		assertThat(partitionForRow(now.id())).isEqualTo("runtime." + partitionOf(0));
		assertThat(partitionForRow(future.id())).isEqualTo("runtime." + partitionOf(2));

		// findById on the composite-PK partitioned table still resolves by id alone.
		assertThat(audits.findById(now.id()).block()).isNotNull();
		// seq (shared identity sequence) was assigned across partitions.
		assertThat(now.version()).isNotNull();
	}

	@Test
	void pruneDropsOldPartitionsAndKeepsInWindow() {
		ensure(-5);
		ensure(0);
		var oldRow = audits.save(auditAt(midMonth(-5), "old")).block();
		var keepRow = audits.save(auditAt(midMonth(0), "keep")).block();
		assertThat(partitionCount(partitionOf(-5))).isEqualTo(1);

		// Prune everything whose whole range precedes the start of (now - 4 months):
		// the -5-month partition (upper bound = month-4 start) qualifies; -0 does not.
		// Prune runs as the OWNER — the restricted runtime role is (correctly) NOT
		// allowed
		// to drop audit partitions (F-audit-prune-role-1). Retention is a maintenance
		// op.
		Instant cutoff = YearMonth.now(ZoneOffset.UTC).minusMonths(4).atDay(1).atStartOfDay(ZoneOffset.UTC).toInstant();
		ownerClient().sql("SELECT runtime.audit_prune_before(:c)").bind("c", cutoff).fetch().one().block();

		assertThat(partitionCount(partitionOf(-5))).isZero(); // partition dropped
		assertThat(audits.findById(oldRow.id()).block()).isNull(); // its row is gone
		assertThat(audits.findById(keepRow.id()).block()).isNotNull(); // in-window row survives

		// Append-only + insert still work on the (now smaller) partitioned table.
		var fresh = audits.save(auditAt(midMonth(0), "fresh")).block();
		assertThat(fresh).isNotNull();
		StepVerifier.create(db.sql("UPDATE runtime.audit_event SET actor = 'x' WHERE id = :id").bind("id", fresh.id())
				.fetch().rowsUpdated()).verifyError(); // rejected (append-only + no UPDATE privilege)
	}

	@Test
	void legalHoldAndComplianceRecordingsAreNotPrunable() {
		var expired = Instant.now().minusSeconds(3600);
		var s1 = sessions.save(session()).block();
		var s2 = sessions.save(session()).block();
		var s3 = sessions.save(session()).block();

		// governance, past retention, no hold -> prunable
		recordings.save(recording(s1.id(), "k-prunable", expired, false, "governance")).block();
		// past retention but legal hold -> NOT prunable
		recordings.save(recording(s2.id(), "k-legalhold", expired, true, "governance")).block();
		// compliance WORM (un-deletable) past retention -> NOT prunable
		recordings.save(recording(s3.id(), "k-compliance", expired, false, "compliance")).block();

		List<String> prunable = db.sql("SELECT object_key FROM runtime.recording_prunable(now())")
				.map(row -> row.get(0, String.class)).all().collectList().block();

		assertThat(prunable).contains("k-prunable");
		assertThat(prunable).doesNotContain("k-legalhold", "k-compliance");
	}

	private SshSession session() {
		return SshSession.create("u", null, null, "deploy", null, null, "standing", List.of("shell"), null, null, null,
				null, 1L, null, Instant.now());
	}

	private RecordingRef recording(UUID sessionId, String objectKey, Instant retentionUntil, boolean legalHold,
			String wormMode) {
		return new RecordingRef(io.sessionlayer.controlplane.data.Uuids.v7(), sessionId, objectKey, "kms://ref", null,
				wormMode, null, retentionUntil, legalHold, "finalized", "asciicast-v2", null, null, null, null, null,
				null, null, null, null);
	}
}
