package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.gateway.GatewayRequestException.Reason;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Registers and finalizes session recordings (Design §12/§12A/§15;
 * FR-AUD-1/2/3/9, FR-DATA-2). The CP owns recording metadata + policy and hands
 * the Gateway a short-lived, single-object WORM upload credential; recording
 * bytes never proxy through the CP.
 *
 * <p>
 * <b>BeginRecording</b> is fail-closed and per-request session-bound: it
 * consumes the single-use recording token (bound to the mTLS caller + session),
 * requires a configured customer key (keystroke capture is always on, so
 * encryption is mandatory — FR-AUD-2), creates the 1:1 {@code recording_ref},
 * and issues a presigned PUT with the WORM object-lock baked in.
 * <b>FinalizeRecording</b> is authorized by the mTLS caller owning the
 * recording's session, commits the write-once integrity metadata, and folds the
 * per-operation SFTP/SCP audit into the correlated audit stream (FR-AUD-9).
 */
@Service
public class RecordingRegistrationService {

	private static final String KEY_ALGO_DEFAULT = "ecies_p256";
	private static final String DEFAULT_KEY_REF = "customer-recording-key";
	private static final Set<String> TERMINAL_STATUSES = Set.of("finalized", "truncated", "failed");
	private static final Pattern SHA256_REF = Pattern.compile("^sha256:[0-9a-f]{64}$");

	private final RecordingTokenService recordingTokens;
	private final OperatorSettingsRepository operatorSettings;
	private final SshSessionRepository sshSessions;
	private final RecordingRefRepository recordings;
	private final WormObjectStore worm;
	private final AuditWriter audit;
	private final TransactionalOperator tx;

	public RecordingRegistrationService(RecordingTokenService recordingTokens,
			OperatorSettingsRepository operatorSettings, SshSessionRepository sshSessions,
			RecordingRefRepository recordings, WormObjectStore worm, AuditWriter audit, TransactionalOperator tx) {
		this.recordingTokens = recordingTokens;
		this.operatorSettings = operatorSettings;
		this.sshSessions = sshSessions;
		this.recordings = recordings;
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
		// or no customer public key. Keystroke capture is always on, so a session that
		// would store keystrokes in the clear must never start (FR-AUD-2, §15).
		Mono<RecordingRegistration> body = operatorSettings.findSingleton().switchIfEmpty(Mono.error(notProvisioned()))
				.flatMap(settings -> {
					byte[] publicKey = settings.recordingCustomerPublicKey();
					if (publicKey == null || publicKey.length == 0) {
						return Mono.error(notProvisioned());
					}
					String keyRef = settings.recordingKeyRef() != null ? settings.recordingKeyRef() : DEFAULT_KEY_REF;
					String algorithm = settings.recordingKeySealAlgorithm() != null
							? settings.recordingKeySealAlgorithm()
							: KEY_ALGO_DEFAULT;
					String wormMode = settings.defaultWormMode();
					Instant retentionUntil = Instant.now().plus(Duration.ofDays(settings.recordingRetentionDays()));
					return register(callerGatewayId, recordingToken, context, publicKey, keyRef, algorithm, wormMode,
							retentionUntil);
				});
		return tx.transactional(body);
	}

	private Mono<RecordingRegistration> register(UUID caller, String recordingToken, RecordingRequestContext context,
			byte[] publicKey, String keyRef, String algorithm, String wormMode, Instant retentionUntil) {
		return recordingTokens.consume(recordingToken, caller, context).flatMap(token -> sshSessions
				.findById(token.sessionId()).switchIfEmpty(Mono.error(notProvisioned())).flatMap(session -> {
					UUID recordingId = Uuids.v7();
					String objectKey = objectKey(session.id(), recordingId);
					RecordingRef ref = RecordingRef.begin(recordingId, session.id(), objectKey, keyRef, wormMode,
							retentionUntil);
					return worm.presignPut(objectKey, wormMode, retentionUntil)
							.flatMap(upload -> recordings.save(ref)
									.then(audit.record(session.identity(), token.principal(), "recording.begin",
											"success", session.id(), session.nodeId(),
											beginDetail(caller, recordingId, objectKey, wormMode, keyRef)))
									.thenReturn(new RecordingRegistration(recordingId, objectKey, wormMode,
											new CustomerKeyMaterial(keyRef, publicKey, algorithm), upload)));
				}));
	}

	/**
	 * Commit a recording's terminal integrity metadata + the file-transfer audit.
	 * Authorized by the mTLS caller owning the recording's session; every mismatch
	 * fails closed with one generic error. Returns the stored terminal status.
	 */
	public Mono<String> finalizeRecording(UUID callerGatewayId, UUID recordingId, String status, String hashChainHead,
			String contentDigest, long byteLen, List<FileTransferAuditEntry> sftpAudit) {
		if (callerGatewayId == null || recordingId == null) {
			return Mono.error(refused());
		}
		if (!TERMINAL_STATUSES.contains(status)) {
			return Mono.error(new GatewayRequestException(Reason.INVALID_ARGUMENT, "invalid recording status"));
		}
		String head = normalizedDigest(hashChainHead);
		String digest = normalizedDigest(contentDigest);
		Long size = byteLen > 0 ? byteLen : null;
		Mono<String> body = recordings.findById(recordingId).switchIfEmpty(Mono.error(refused())).flatMap(
				ref -> sshSessions.findById(ref.sessionId()).switchIfEmpty(Mono.error(refused())).flatMap(session -> {
					if (!callerGatewayId.equals(session.gatewayId())) {
						return Mono.error(refused());
					}
					// A recording finalizes once. A same-status re-finalize is idempotent (a
					// lost-response retry), but relabeling an already-terminal recording to a
					// DIFFERENT status (e.g. finalized→failed to hide it) is refused — the
					// crown-jewel provenance is already frozen by the write-once trigger (§15).
					if (!"recording".equals(ref.status()) && !ref.status().equals(status)) {
						return Mono.error(
								new GatewayRequestException(Reason.FAILED_PRECONDITION, "recording already finalized"));
					}
					RecordingRef finalized = ref.finalized(head, digest, size, status);
					return recordings.save(finalized).then(writeTransferAudit(session, sftpAudit))
							.then(audit.record(session.identity(), recordingId.toString(), "recording.finalize",
									finalizeOutcome(status), session.id(), session.nodeId(),
									finalizeDetail(callerGatewayId, recordingId, status, byteLen, digest, head)))
							.thenReturn(status);
				}));
		return tx.transactional(body);
	}

	// One audit_event per decoded SFTP/SCP operation (FR-AUD-1), metadata only,
	// correlated by session_id (FR-AUD-9). Sequential (concatMap) — one tx
	// connection.
	private Mono<Void> writeTransferAudit(SshSession session, List<FileTransferAuditEntry> sftpAudit) {
		if (sftpAudit == null || sftpAudit.isEmpty()) {
			return Mono.empty();
		}
		return Flux
				.fromIterable(sftpAudit).concatMap(entry -> audit.record(session.identity(), entry.path(),
						"sftp." + entry.operation(), "success", session.id(), session.nodeId(), transferDetail(entry)))
				.then();
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
		if (entry.sha256() != null && !entry.sha256().isBlank()) {
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
