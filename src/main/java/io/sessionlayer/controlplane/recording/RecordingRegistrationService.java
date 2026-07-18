package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditRecord;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.gateway.GatewayRequestException.Reason;
import io.sessionlayer.controlplane.recording.RecordingStore.PresignedAccess;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

/**
 * Registers, issues upload credentials for, and finalizes session recordings
 * (Design §12/§12A/§15; FR-AUD-1/2/3/9, FR-DATA-2). The CP owns recording
 * metadata + policy and hands the Gateway a short-lived, single-object WORM
 * upload credential; recording bytes never proxy through the CP.
 *
 * <p>
 * Lifecycle: <b>BeginRecording</b> (session start — fail-closed, session-bound:
 * consume the recording token, validate + return the customer key, create the
 * 1:1 {@code recording_ref}) → <b>RequestUpload</b> (session end — authorize by
 * owner, issue a short-lived presigned PUT so the credential's life is the
 * upload, not the session) → <b>FinalizeRecording</b> (commit write-once
 * integrity + the correlated SFTP audit). No S3 network I/O ever runs inside a
 * DB transaction.
 */
@Service
public class RecordingRegistrationService {

	private static final Logger LOG = LoggerFactory.getLogger(RecordingRegistrationService.class);

	private static final String KEY_ALGO_DEFAULT = "ecies_p256";
	private static final String DEFAULT_KEY_REF = "customer-recording-key";
	private static final Set<String> TERMINAL_STATUSES = Set.of("finalized", "truncated", "failed");
	private static final Pattern SHA256_REF = Pattern.compile("^sha256:[0-9a-f]{64}$");

	private final RecordingTokenService recordingTokens;
	private final OperatorSettingsRepository operatorSettings;
	private final SshSessionRepository sshSessions;
	private final RecordingRefRepository recordings;
	private final NodeRepository nodes;
	private final RecordingStore worm;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public RecordingRegistrationService(RecordingTokenService recordingTokens,
			OperatorSettingsRepository operatorSettings, SshSessionRepository sshSessions,
			RecordingRefRepository recordings, NodeRepository nodes, RecordingStore worm, AuditEventStore audit,
			TransactionalOperator tx) {
		this.recordingTokens = recordingTokens;
		this.operatorSettings = operatorSettings;
		this.sshSessions = sshSessions;
		this.recordings = recordings;
		this.nodes = nodes;
		this.worm = worm;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<RecordingRegistration> beginRecording(UUID callerGatewayId, String recordingToken,
			RecordingRequestContext context) {
		if (callerGatewayId == null) {
			return Mono.error(refused());
		}
		// Fail closed when recording is un-provisioned: no operator_settings singleton,
		// no customer key, or an unusable key. Keystroke capture is always on, so a
		// session that would store keystrokes it can't seal must never start
		// (FR-AUD-2).
		Mono<RecordingRegistration> body = operatorSettings.findSingleton().switchIfEmpty(Mono.error(notProvisioned()))
				.flatMap(settings -> {
					byte[] publicKey = settings.recordingCustomerPublicKey();
					String algorithm = settings.recordingKeySealAlgorithm() != null
							? settings.recordingKeySealAlgorithm()
							: KEY_ALGO_DEFAULT;
					if (publicKey == null || publicKey.length == 0
							|| !CustomerPublicKeys.isValid(publicKey, algorithm)) {
						return Mono.error(notProvisioned());
					}
					String keyRef = settings.recordingKeyRef() != null ? settings.recordingKeyRef() : DEFAULT_KEY_REF;
					String wormMode = settings.defaultWormMode();
					// Retention floor (>= 1 day) so a mis-set 0 can't yield a lock that expires
					// immediately; the DB CHECK enforces it too.
					int retentionDays = Math.max(1, settings.recordingRetentionDays());
					Instant retentionUntil = Instant.now().plus(Duration.ofDays(retentionDays));
					return register(callerGatewayId, recordingToken, context, publicKey, keyRef, algorithm, wormMode,
							retentionUntil);
				});
		return tx.transactional(body).onErrorResume(
				error -> failureAudit("recording.begin", callerGatewayId, error).then(Mono.error(error)));
	}

	private Mono<RecordingRegistration> register(UUID caller, String recordingToken, RecordingRequestContext context,
			byte[] publicKey, String keyRef, String algorithm, String wormMode, Instant retentionUntil) {
		return recordingTokens.consume(recordingToken, caller, context).flatMap(token -> sshSessions
				.findById(token.sessionId()).switchIfEmpty(Mono.error(notProvisioned())).flatMap(session -> {
					// Break-glass recording is MANDATORY strict and not configurable-off (FR-ACC-6,
					// §7), keyed on the ACCESS MODEL directly: re-assert a usable customer key for
					// a break-glass session so a future best-effort/downgrade recording path can
					// never apply to break-glass. Today it is redundant with the fail-closed key
					// check in beginRecording (every recording is sealed to the key or the session
					// never starts) — by design; the Gateway also forces strict from the signed
					// access model.
					if ("breakglass".equals(session.accessModel()) && (publicKey == null || publicKey.length == 0
							|| !CustomerPublicKeys.isValid(publicKey, algorithm))) {
						return Mono.error(notProvisioned());
					}
					UUID recordingId = Uuids.v7();
					String objectKey = objectKey(session.id(), recordingId);
					RecordingRef ref = RecordingRef.begin(recordingId, session.id(), objectKey, keyRef, wormMode,
							retentionUntil);
					return nodeLabels(session.nodeId()).flatMap(labels -> recordings.save(ref)
							.then(audit.record(sessionEvent(session, labels, session.identity(), token.principal(),
									"recording.begin", "success")
									.detail(beginDetail(caller, recordingId, objectKey, wormMode, keyRef)).build()))
							.thenReturn(new RecordingRegistration(recordingId, objectKey, wormMode,
									new CustomerKeyMaterial(keyRef, publicKey, algorithm))));
				}));
	}

	/**
	 * Issue the short-lived, single-object WORM upload credential for a registered
	 * recording, at the moment the Gateway is ready to PUT (Design §12.2).
	 * Authorized by the mTLS caller owning the recording's session; the presigned
	 * PUT is bound to the recording's stored object key + WORM mode + retain-until,
	 * and no S3 I/O runs inside a DB transaction. Every mismatch fails closed
	 * generically.
	 */
	public Mono<PresignedAccess> requestUpload(UUID callerGatewayId, UUID recordingId) {
		if (callerGatewayId == null || recordingId == null) {
			return Mono.error(refused());
		}
		Mono<PresignedAccess> body = recordings.findById(recordingId).switchIfEmpty(Mono.error(refused())).flatMap(
				ref -> sshSessions.findById(ref.sessionId()).switchIfEmpty(Mono.error(refused())).flatMap(session -> {
					if (!callerGatewayId.equals(session.gatewayId())) {
						return Mono.error(refused());
					}
					// F-recording-worm-version-1: a terminal recording gets NO fresh presigned
					// PUT — else a compromised/buggy Gateway could shadow the finalized,
					// WORM-locked object with a later version to the same key (§15). Uploads
					// are only issued while the recording is still open.
					if (!"recording".equals(ref.status())) {
						return Mono.error(refused());
					}
					Instant retainUntil = ref.retentionUntil() != null
							? ref.retentionUntil()
							: Instant.now().plus(Duration.ofDays(1));
					return nodeLabels(session.nodeId()).flatMap(labels -> worm.ensureReady()
							.then(worm.presignUpload(ref.objectKey(), ref.wormMode(), retainUntil))
							.flatMap(upload -> audit.record(sessionEvent(session, labels, session.identity(),
									recordingId.toString(), "recording.upload", "success")
									.detail(uploadDetail(callerGatewayId, recordingId, ref.objectKey())).build())
									.thenReturn(upload)));
				}));
		return body.onErrorResume(
				error -> failureAudit("recording.upload", callerGatewayId, error).then(Mono.error(error)));
	}

	/**
	 * Commit a recording's terminal integrity metadata + the file-transfer audit
	 * (idempotent on the first terminal transition). Authorized by the mTLS caller
	 * owning the recording's session; every mismatch fails closed generically.
	 * Returns the stored terminal status.
	 */
	public Mono<String> finalizeRecording(UUID callerGatewayId, UUID recordingId, String status, String hashChainHead,
			String contentDigest, String objectVersionId, long byteLen, List<FileTransferAuditEntry> sftpAudit) {
		if (callerGatewayId == null || recordingId == null) {
			return Mono.error(refused());
		}
		if (!TERMINAL_STATUSES.contains(status)) {
			return Mono.error(new GatewayRequestException(Reason.INVALID_ARGUMENT, "invalid recording status"));
		}
		if (sftpAudit != null && sftpAudit.size() > SftpAuditPolicy.MAX_BATCH) {
			return Mono.error(new GatewayRequestException(Reason.INVALID_ARGUMENT, "sftp audit batch too large"));
		}
		String head = normalizedDigest(hashChainHead);
		String digest = normalizedDigest(contentDigest);
		// The object-store version id replay/export pins so a later shadow PUT to the
		// same key can't be served (F-recording-worm-version-1 / §15). Empty ⇒ null (an
		// N-1 Gateway that predates the field, or a non-versioned store).
		String versionId = (objectVersionId == null || objectVersionId.isBlank()) ? null : objectVersionId;
		Long size = byteLen > 0 ? byteLen : null;
		Mono<String> body = recordings.findById(recordingId).switchIfEmpty(Mono.error(refused())).flatMap(
				ref -> sshSessions.findById(ref.sessionId()).switchIfEmpty(Mono.error(refused())).flatMap(session -> {
					if (!callerGatewayId.equals(session.gatewayId())) {
						return Mono.error(refused());
					}
					if (!"recording".equals(ref.status())) {
						// Already finalized: a same-status re-finalize is an idempotent no-op
						// (write NOTHING — no duplicate audit rows); relabeling to a DIFFERENT
						// terminal status (e.g. finalized→failed to hide it) is refused (§15).
						return ref.status().equals(status)
								? Mono.just(status)
								: Mono.error(new GatewayRequestException(Reason.FAILED_PRECONDITION,
										"recording already finalized"));
					}
					RecordingRef finalized = ref.finalized(head, digest, versionId, size, status);
					return nodeLabels(session.nodeId()).flatMap(labels -> recordings.save(finalized)
							.then(writeTransferAudit(session, labels, sftpAudit))
							.then(audit.record(sessionEvent(session, labels, session.identity(), recordingId.toString(),
									"recording.finalize", finalizeOutcome(status))
									.detail(finalizeDetail(callerGatewayId, recordingId, status, byteLen, digest, head))
									.build()))
							.thenReturn(status));
				}));
		return tx.transactional(body);
	}

	// One audit_event per decoded SFTP/SCP operation (FR-AUD-1), metadata only,
	// normalized/validated at the boundary, correlated by session_id (FR-AUD-9).
	// Sequential (concatMap) — one tx connection.
	private Mono<Void> writeTransferAudit(SshSession session, Map<String, String> nodeLabels,
			List<FileTransferAuditEntry> sftpAudit) {
		if (sftpAudit == null || sftpAudit.isEmpty()) {
			return Mono.empty();
		}
		return Flux.fromIterable(sftpAudit).map(SftpAuditPolicy::normalize)
				.concatMap(entry -> audit.record(sessionEvent(session, nodeLabels, session.identity(), entry.path(),
						"sftp." + entry.operation(), "success").detail(transferDetail(entry)).build()))
				.then();
	}

	// Every in-session recording event inherits the session's access model, its
	// node-label snapshot and the FR-AUD-9 correlation key, so one correlation_id
	// search returns the recording (run/replay) alongside the connect + JIT
	// approval
	// that authorized it — for a node-label-scoped auditor too
	// (F-audit-chainscope-1).
	private static AuditRecord.Builder sessionEvent(SshSession session, Map<String, String> nodeLabels, String actor,
			String subject, String action, String outcome) {
		return AuditRecord.builder(actor, subject, action, outcome).session(session.id()).node(session.nodeId())
				.accessModel(session.accessModel()).nodeLabels(nodeLabels).correlationId(session.correlationId());
	}

	// The session's node label snapshot for its audit events (one read; empty when
	// the session has no node).
	private Mono<Map<String, String>> nodeLabels(UUID nodeId) {
		if (nodeId == null) {
			return Mono.just(Map.of());
		}
		return nodes.findById(nodeId).map(node -> labelsOf(node.resolvedLabels())).defaultIfEmpty(Map.of());
	}

	private static Map<String, String> labelsOf(JsonNode resolvedLabels) {
		Map<String, String> labels = new HashMap<>();
		if (resolvedLabels != null && resolvedLabels.isObject()) {
			for (var entry : resolvedLabels.properties()) {
				labels.put(entry.getKey(), entry.getValue().asString());
			}
		}
		return labels;
	}

	// Best-effort, OUT-OF-BAND failure record: recording is mandatory, so a failed
	// Begin/RequestUpload must reach the audit stream, not just app logs (FR-AUD).
	// Its own transaction (the main one rolled back); a lost audit write must not
	// mask the original error.
	private Mono<Void> failureAudit(String action, UUID caller, Throwable error) {
		Map<String, String> detail = new HashMap<>();
		detail.put("gateway_id", caller == null ? "unknown" : caller.toString());
		detail.put("reason", reasonCode(error));
		return audit.record(caller == null ? "unknown" : caller.toString(), null, action, "failure", null, null, detail)
				.onErrorResume(auditError -> {
					LOG.error("{} failure-audit write failed (original error still raised): {}", action,
							auditError.toString());
					return Mono.empty();
				});
	}

	private static String reasonCode(Throwable error) {
		return error instanceof GatewayRequestException request
				? request.reason().name()
				: error.getClass().getSimpleName();
	}

	private static String objectKey(UUID sessionId, UUID recordingId) {
		return "recordings/" + sessionId + "/" + recordingId + ".cast.enc";
	}

	private static Map<String, String> beginDetail(UUID caller, UUID recordingId, String objectKey, String wormMode,
			String keyRef) {
		Map<String, String> detail = new HashMap<>();
		detail.put("gateway_id", caller.toString());
		detail.put("recording_id", recordingId.toString());
		detail.put("object_key", objectKey);
		detail.put("worm_mode", wormMode);
		detail.put("key_ref", keyRef);
		return detail;
	}

	private static Map<String, String> uploadDetail(UUID caller, UUID recordingId, String objectKey) {
		Map<String, String> detail = new HashMap<>();
		detail.put("gateway_id", caller.toString());
		detail.put("recording_id", recordingId.toString());
		detail.put("object_key", objectKey);
		return detail;
	}

	private static Map<String, String> finalizeDetail(UUID caller, UUID recordingId, String status, long byteLen,
			String digest, String head) {
		Map<String, String> detail = new HashMap<>();
		detail.put("gateway_id", caller.toString());
		detail.put("recording_id", recordingId.toString());
		detail.put("status", status);
		detail.put("byte_len", Long.toString(byteLen));
		if (digest != null) {
			detail.put("content_digest", digest);
		}
		if (head != null) {
			detail.put("hash_chain_head", head);
		}
		return detail;
	}

	private static Map<String, String> transferDetail(FileTransferAuditEntry entry) {
		Map<String, String> detail = new HashMap<>();
		detail.put("path", entry.path());
		detail.put("direction", entry.direction());
		detail.put("size", Long.toString(entry.size()));
		if (entry.sha256() != null) {
			detail.put("sha256", entry.sha256());
		}
		return detail;
	}

	// A FAILED recording is recorded loudly (never silently dropped); a finalized
	// or
	// truncated (valid partial) recording is a success outcome.
	private static String finalizeOutcome(String status) {
		return "failed".equals(status) ? "failure" : "success";
	}

	// The digest columns are "sha256:<64-hex>" (content_digest carries a DB CHECK);
	// a malformed non-empty value fails closed rather than corrupt the row.
	private static String normalizedDigest(String value) {
		if (value == null || value.isBlank()) {
			return null;
		}
		String trimmed = value.trim();
		if (!SHA256_REF.matcher(trimmed).matches()) {
			throw new GatewayRequestException(Reason.INVALID_ARGUMENT, "invalid digest");
		}
		return trimmed;
	}

	private static GatewayRequestException refused() {
		return new GatewayRequestException(Reason.PERMISSION_DENIED, "recording request refused");
	}

	private static GatewayRequestException notProvisioned() {
		return new GatewayRequestException(Reason.FAILED_PRECONDITION, "recording is not provisioned");
	}
}
