package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.web.ApiProblemException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Recording retention + governance lifecycle (Part D, FR-AUD-3/6): the operator
 * legal hold, the privileged/audited governance-delete (the GDPR erasure escape
 * hatch), and the automated retention pruner. In every path the encrypted
 * <b>object</b> is deleted through the pluggable {@link RecordingStore} while
 * the provenance <b>row</b> is retained and marked pruned — so the audit trail
 * that a recording existed (and was erased, by whom) survives (§15). WORM
 * rules: a legal hold blocks deletion in either mode, and a
 * {@code compliance}-mode object is truly un-deletable (object-lock, reused
 * from S9).
 *
 * <p>
 * Both delete paths <b>atomically claim</b> the row (a conditional UPDATE that
 * re-asserts un-held/un-pruned/governance at delete time) before touching the
 * object, so a legal hold placed after an eligibility read cannot be raced into
 * erasing held evidence, and two nodes cannot both delete (§11, HA-safe).
 */
@Service
public class RecordingRetentionService {

	private static final Logger LOG = LoggerFactory.getLogger(RecordingRetentionService.class);

	// Bound one prune cycle so a large backlog drains across cycles without blowing
	// the cycle's time budget (a stuck cycle must not wedge the scheduler).
	private static final int MAX_BATCH = 1000;

	// deleted_by stays null on a retention prune (automated, no human actor); the
	// audit actor is a system sentinel (the stream's actor column is NOT NULL).
	private static final String RETENTION_ACTOR = "system:retention";

	// Atomically claim a row for deletion: only a still-un-held, un-pruned,
	// non-compliance row is claimed (RETURNING the object key), so the
	// hold/compliance
	// check and the erase decision are one indivisible step (no TOCTOU, no HA
	// double-claim). version+updated_at are bumped to keep optimistic-lock
	// semantics.
	private static final String CLAIM_RETENTION = """
			UPDATE runtime.recording_ref
			   SET pruned_at = :now, delete_mode = 'retention', version = version + 1, updated_at = now()
			 WHERE id = :id AND pruned_at IS NULL AND legal_hold = false AND worm_mode IS DISTINCT FROM 'compliance'
			RETURNING object_key, worm_mode, session_id""";

	private static final String CLAIM_GOVERNANCE = """
			UPDATE runtime.recording_ref
			   SET pruned_at = :now, delete_mode = 'governance', deleted_by = :actor, version = version + 1, updated_at = now()
			 WHERE id = :id AND pruned_at IS NULL AND legal_hold = false AND worm_mode IS DISTINCT FROM 'compliance'
			RETURNING object_key, worm_mode, session_id""";

	// F-recording-prune-confirm-1: the atomic claim commits pruned_at FIRST (to
	// close
	// the legal-hold TOCTOU), but the OBJECT delete can still fail. If it does,
	// roll
	// the claim back so the row is re-selected next cycle — otherwise metadata
	// reports
	// "erased" while the encrypted bytes persist (false erasure + orphaned object).
	// The
	// re-claim re-asserts hold/compliance, so a hold placed meanwhile still
	// protects.
	private static final String UNCLAIM = """
			UPDATE runtime.recording_ref
			   SET pruned_at = NULL, delete_mode = NULL, deleted_by = NULL, version = version + 1, updated_at = now()
			 WHERE id = :id AND pruned_at IS NOT NULL""";

	private final RecordingRefRepository recordings;
	private final SshSessionRepository sessions;
	private final RecordingStore recordingStore;
	private final AuditEventStore audit;
	private final DatabaseClient db;

	public RecordingRetentionService(RecordingRefRepository recordings, SshSessionRepository sessions,
			RecordingStore recordingStore, AuditEventStore audit, DatabaseClient db) {
		this.recordings = recordings;
		this.sessions = sessions;
		this.recordingStore = recordingStore;
		this.audit = audit;
		this.db = db;
	}

	// Idempotent by desired state: setting a hold to its current value is a no-op
	// (no version bump, no duplicate audit) — the response still reflects the
	// state.
	public Mono<RecordingSummary> setLegalHold(String actor, UUID recordingId, boolean held, String reason) {
		return loadRef(recordingId).flatMap(ref -> {
			if (ref.legalHold() == held) {
				return summaryOf(ref);
			}
			Map<String, String> detail = new LinkedHashMap<>();
			detail.put("held", Boolean.toString(held));
			if (held && reason != null && !reason.isBlank()) {
				detail.put("reason", reason);
			}
			return recordings.save(ref.withLegalHold(held, reason))
					.flatMap(saved -> audit.record(actor, saved.id().toString(), "recording.legal_hold", "success",
							saved.sessionId(), null, detail).then(summaryOf(saved)));
		});
	}

	// Governance-mode erasure (FR-AUD-3/6). The pre-checks give the caller a
	// precise
	// 404/409; the atomic claim then re-asserts them at delete time (closes the
	// legal-hold TOCTOU + HA double-delete). Idempotent: an already-pruned
	// recording
	// is a 204 no-op; a lost claim race is a 409 (retry → 204 or the real 409).
	public Mono<Void> governanceDelete(String actor, UUID recordingId) {
		return loadRef(recordingId).flatMap(ref -> {
			if (ref.prunedAt() != null) {
				return Mono.empty();
			}
			if (ref.legalHold()) {
				return Mono.error(ApiProblemException.conflict("recording is under legal hold and cannot be deleted"));
			}
			if ("compliance".equals(ref.wormMode())) {
				return Mono.error(ApiProblemException.conflict("compliance-mode recordings are un-deletable"));
			}
			return claim(CLAIM_GOVERNANCE,
					spec -> spec.bind("now", Instant.now()).bind("actor", actor).bind("id", recordingId))
					.switchIfEmpty(
							Mono.error(ApiProblemException.conflict("recording was concurrently modified; retry")))
					.flatMap(claimed -> recordingStore.deleteObject(claimed.objectKey(), claimed.wormMode())
							.then(audit.record(actor, recordingId.toString(), "recording.delete", "success",
									claimed.sessionId(), null, Map.of("delete_mode", "governance")))
							// The object delete failed: roll the claim back + audit, then surface the
							// error so the caller never gets a false 204 (F-recording-prune-confirm-1).
							.onErrorResume(
									error -> unclaim(recordingId, claimed, actor, "recording.delete", "governance")
											.then(Mono.error(error))))
					.then();
		});
	}

	// Erase every governance recording past retention (bounded per cycle); the
	// atomic
	// claim per row re-checks eligibility, so a hold placed since the prunable
	// query
	// still protects the object. Per-row failures are logged, never fatal.
	public Mono<Void> prune(String trigger) {
		Instant now = Instant.now();
		AtomicLong deleted = new AtomicLong();
		AtomicLong skipped = new AtomicLong();
		AtomicLong failed = new AtomicLong();
		return db.sql("SELECT id FROM runtime.recording_prunable(:cutoff) LIMIT :limit").bind("cutoff", now)
				.bind("limit", MAX_BATCH).map((row, meta) -> row.get("id", UUID.class)).all()
				.concatMap(id -> pruneOne(id, now).doOnNext(pruned -> (pruned ? deleted : skipped).incrementAndGet())
						.onErrorResume(error -> {
							failed.incrementAndGet();
							LOG.warn("retention prune of recording {} failed; retrying next cycle", id, error);
							return Mono.empty();
						}))
				.then(Mono.<Void>fromRunnable(
						() -> LOG.info("recording retention prune ({}) complete: deleted={} skipped={} failed={}",
								trigger, deleted.get(), skipped.get(), failed.get())))
				.onErrorResume(error -> {
					LOG.warn("recording retention prune ({}) failed; retrying next cycle", trigger, error);
					return Mono.empty();
				});
	}

	private Mono<Boolean> pruneOne(UUID recordingId, Instant now) {
		return claim(CLAIM_RETENTION, spec -> spec.bind("now", now).bind("id", recordingId))
				.flatMap(
						claimed -> recordingStore.deleteObject(claimed.objectKey(), claimed.wormMode())
								.then(audit.record(RETENTION_ACTOR, recordingId.toString(), "recording.prune",
										"success", claimed.sessionId(), null, Map.of("delete_mode", "retention")))
								.thenReturn(Boolean.TRUE)
								// The object delete failed: roll the claim back + audit so the row is
								// re-pruned next cycle rather than falsely reported erased
								// (F-recording-prune-confirm-1). The error propagates to prune()'s
								// per-row onErrorResume (counted failed).
								.onErrorResume(error -> unclaim(recordingId, claimed, RETENTION_ACTOR,
										"recording.prune", "retention").then(Mono.error(error))))
				.defaultIfEmpty(Boolean.FALSE);
	}

	// Roll back a claim whose object delete failed, and audit the failed attempt,
	// so
	// the recording is NOT falsely reported erased (F-recording-prune-confirm-1).
	private Mono<Void> unclaim(UUID recordingId, Claimed claimed, String actor, String action, String mode) {
		return db.sql(UNCLAIM).bind("id", recordingId).fetch().rowsUpdated()
				.then(audit.record(actor, recordingId.toString(), action, "error", claimed.sessionId(), null,
						Map.of("delete_mode", mode, "reason", "object_delete_failed")))
				.then();
	}

	private Mono<Claimed> claim(String sql, java.util.function.UnaryOperator<DatabaseClient.GenericExecuteSpec> binds) {
		return binds.apply(db.sql(sql)).map((row, meta) -> new Claimed(row.get("object_key", String.class),
				row.get("worm_mode", String.class), row.get("session_id", UUID.class))).all().next();
	}

	private Mono<RecordingSummary> summaryOf(RecordingRef ref) {
		return sessions.findById(ref.sessionId()).map(session -> RecordingSummary.of(ref, session))
				.defaultIfEmpty(RecordingSummary.of(ref, null));
	}

	private Mono<RecordingRef> loadRef(UUID recordingId) {
		return recordings.findById(recordingId)
				.switchIfEmpty(Mono.error(ApiProblemException.notFound("recording", recordingId)));
	}

	private record Claimed(String objectKey, String wormMode, UUID sessionId) {
	}
}
