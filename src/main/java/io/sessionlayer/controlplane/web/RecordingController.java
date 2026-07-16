package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.RecordingsApi;
import io.sessionlayer.controlplane.api.model.LegalHoldRequest;
import io.sessionlayer.controlplane.api.model.RecordingPage;
import io.sessionlayer.controlplane.api.model.RecordingResource;
import io.sessionlayer.controlplane.api.model.SignedUrl;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.recording.RecordingAccessService;
import io.sessionlayer.controlplane.recording.RecordingRetentionService;
import io.sessionlayer.controlplane.recording.RecordingStore.PresignedAccess;
import io.sessionlayer.controlplane.recording.RecordingSummary;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.net.URI;
import java.time.Instant;
import java.util.UUID;
import java.util.function.BiFunction;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Session-recording admin surface (Design §12.2, FR-AUD-3/5/6, FR-PADM-2/3).
 * List/get expose metadata (never bytes); replay/export issue short-lived
 * signed URLs to the still-encrypted object (bytes never proxy through the CP,
 * which cannot decrypt them), scope-gated + audited; legal hold + governance
 * delete are the {@code recording:delete}-privileged, audited custody surface.
 */
@RestController
public class RecordingController implements RecordingsApi {

	private final PlatformAccess platformAccess;
	private final CurrentAuthentication currentAuthentication;
	private final IdempotencyService idempotency;
	private final RecordingAccessService access;
	private final RecordingRetentionService retention;

	public RecordingController(PlatformAccess platformAccess, CurrentAuthentication currentAuthentication,
			IdempotencyService idempotency, RecordingAccessService access, RecordingRetentionService retention) {
		this.platformAccess = platformAccess;
		this.currentAuthentication = currentAuthentication;
		this.idempotency = idempotency;
		this.access = access;
		this.retention = retention;
	}

	@Override
	public Mono<ResponseEntity<RecordingPage>> listRecordings(String cursor, Integer limit, UUID sessionId,
			String identity, UUID nodeId, ServerWebExchange exchange) {
		return platformAccess.withPermission(PlatformPermissions.RECORDING_REPLAY,
				subject -> access.list(cursor, limit, sessionId, identity, nodeId)
						.map(page -> ResponseEntity
								.ok(new RecordingPage(page.items().stream().map(this::toResource).toList())
										.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<RecordingResource>> getRecording(UUID recordingId, ServerWebExchange exchange) {
		return platformAccess.withPermission(PlatformPermissions.RECORDING_REPLAY,
				subject -> access.get(recordingId).map(summary -> ResponseEntity.ok(toResource(summary))));
	}

	@Override
	public Mono<ResponseEntity<SignedUrl>> replayRecording(UUID recordingId, String idempotencyKey,
			ServerWebExchange exchange) {
		return issue(recordingId, idempotencyKey, exchange, access::replay);
	}

	@Override
	public Mono<ResponseEntity<SignedUrl>> exportRecording(UUID recordingId, String idempotencyKey,
			ServerWebExchange exchange) {
		return issue(recordingId, idempotencyKey, exchange, access::export);
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteRecording(UUID recordingId, String idempotencyKey,
			ServerWebExchange exchange) {
		return platformAccess.withPermission(PlatformPermissions.RECORDING_DELETE, subject -> {
			Mono<ResponseEntity<Void>> action = retention.governanceDelete(subject.identity(), recordingId)
					.thenReturn(ResponseEntity.noContent().<Void>build());
			return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
					ApiConversions.path(exchange), null, Void.class, action);
		});
	}

	@Override
	public Mono<ResponseEntity<RecordingResource>> setRecordingLegalHold(UUID recordingId,
			Mono<LegalHoldRequest> legalHoldRequest, String idempotencyKey, ServerWebExchange exchange) {
		return platformAccess.withPermission(PlatformPermissions.RECORDING_DELETE,
				subject -> legalHoldRequest
						.switchIfEmpty(
								Mono.error(ApiProblemException.validation("a legal-hold body with 'held' is required")))
						.flatMap(req -> {
							if (req.getHeld() == null) {
								return Mono.error(ApiProblemException.validation("'held' is required"));
							}
							Mono<ResponseEntity<RecordingResource>> action = retention
									.setLegalHold(subject.identity(), recordingId, req.getHeld(), req.getReason())
									.map(summary -> ResponseEntity.ok(toResource(summary)));
							return idempotency.execute(idempotencyKey, subject.identity(),
									ApiConversions.method(exchange), ApiConversions.path(exchange), req,
									RecordingResource.class, action);
						}));
	}

	// Replay/export: resolve the caller, run the scoped access (which loads the
	// recording, builds its scope, authorizes + audits), and render the signed URL.
	// An out-of-scope deny completes empty → a bodiless 403 (no
	// existence/permission
	// disclosure), matching the platform-RBAC gate.
	private Mono<ResponseEntity<SignedUrl>> issue(UUID recordingId, String idempotencyKey, ServerWebExchange exchange,
			BiFunction<PlatformSubject, UUID, Mono<PresignedAccess>> op) {
		return currentAuthentication.subject().flatMap(subject -> {
			Mono<ResponseEntity<SignedUrl>> action = op.apply(subject, recordingId)
					.map(presigned -> ResponseEntity.ok(toSignedUrl(presigned)));
			return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
					ApiConversions.path(exchange), null, SignedUrl.class, action);
		}).switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}

	private SignedUrl toSignedUrl(PresignedAccess presigned) {
		return new SignedUrl(URI.create(presigned.url()), presigned.method(),
				ApiConversions.toOffset(Instant.ofEpochSecond(presigned.expiresAtEpochSeconds())));
	}

	private RecordingResource toResource(RecordingSummary summary) {
		RecordingResource resource = new RecordingResource(summary.id(), summary.sessionId());
		resource.setIdentity(summary.identity());
		resource.setNodeId(summary.nodeId());
		resource.setFormat(summary.format());
		resource.setStatus(summary.status());
		resource.setWormMode(summary.wormMode());
		resource.setSizeBytes(summary.sizeBytes());
		resource.setHashChainHead(summary.hashChainHead());
		resource.setEncryptionKeyRef(summary.encryptionKeyRef());
		resource.setLegalHold(summary.legalHold());
		resource.setRetentionUntil(ApiConversions.toOffset(summary.retentionUntil()));
		resource.setPrunedAt(ApiConversions.toOffset(summary.prunedAt()));
		resource.setStartedAt(ApiConversions.toOffset(summary.startedAt()));
		resource.setEndedAt(ApiConversions.toOffset(summary.endedAt()));
		resource.setCreatedAt(ApiConversions.toOffset(summary.createdAt()));
		return resource;
	}
}
