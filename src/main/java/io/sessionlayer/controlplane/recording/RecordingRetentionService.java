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
 */
@Service
public class RecordingRetentionService {

	private static final Logger LOG = LoggerFactory.getLogger(RecordingRetentionService.class);

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

	// Governance-mode erasure (FR-AUD-3/6). Idempotent: an already-pruned recording
	// is a 204 no-op. A legal hold or compliance mode refuses with a 409 — the
	// store
	// also refuses compliance (defense in depth), but we never even attempt it.
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
			Instant now = Instant.now();
			Map<String, String> detail = Map.of("delete_mode", "governance");
			return recordingStore.deleteObject(ref.objectKey(), ref.wormMode())
					.then(recordings.save(ref.pruned("governance", actor, now))).flatMap(saved -> audit.record(actor,
							saved.id().toString(), "recording.delete", "success", saved.sessionId(), null, detail))
					.then();
		});
	}

	// Delete the encrypted object of every governance recording past its
	// retention_until (legal-held + compliance are never returned by the function),
	// mark the row pruned, and audit. Per-row failures are logged, never fatal.
	public Mono<Void> prune(String trigger) {
		Instant now = Instant.now();
		return db.sql("SELECT id FROM runtime.recording_prunable(:cutoff)").bind("cutoff", now)
				.map((row, meta) -> row.get("id", UUID.class)).all()
				.concatMap(id -> pruneOne(id, now).onErrorResume(e -> {
					LOG.warn("retention prune of recording {} failed; retrying next cycle", id, e);
					return Mono.empty();
				})).then().doOnSuccess(v -> LOG.debug("recording retention prune ({}) complete", trigger))
				.onErrorResume(error -> {
					LOG.warn("recording retention prune ({}) failed; retrying next cycle", trigger, error);
					return Mono.empty();
				});
	}

	// deleted_by stays null on the row (automated, no human actor); the audit actor
	// is a system sentinel (the stream's actor column is NOT NULL).
	private static final String RETENTION_ACTOR = "system:retention";

	// Re-read the row before erasing: skip one a concurrent governance delete
	// already
	// pruned (TOCTOU vs the prunable query), and pass its actual worm mode so the
	// store's compliance refusal still applies if the SQL filter ever regressed.
	private Mono<Void> pruneOne(UUID recordingId, Instant now) {
		return recordings.findById(recordingId).filter(ref -> ref.prunedAt() == null)
				.flatMap(ref -> recordingStore.deleteObject(ref.objectKey(), ref.wormMode())
						.then(recordings.save(ref.pruned("retention", null, now))))
				.flatMap(saved -> audit.record(RETENTION_ACTOR, saved.id().toString(), "recording.prune", "success",
						saved.sessionId(), null, Map.of("delete_mode", "retention")))
				.then();
	}

	private Mono<RecordingSummary> summaryOf(RecordingRef ref) {
		return sessions.findById(ref.sessionId()).map(session -> RecordingSummary.of(ref, session))
				.defaultIfEmpty(RecordingSummary.of(ref, null));
	}

	private Mono<RecordingRef> loadRef(UUID recordingId) {
		return recordings.findById(recordingId)
				.switchIfEmpty(Mono.error(ApiProblemException.notFound("recording", recordingId)));
	}
}
