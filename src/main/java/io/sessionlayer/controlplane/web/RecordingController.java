package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.RecordingsApi;
import io.sessionlayer.controlplane.api.model.LegalHoldRequest;
import io.sessionlayer.controlplane.api.model.RecordingPage;
import io.sessionlayer.controlplane.api.model.RecordingResource;
import io.sessionlayer.controlplane.api.model.SignedUrl;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Session-recording admin surface (Design §12.2). Placeholder implementation —
 * Session 18 (Part C/D) replaces the bodies with signed-URL replay/export
 * (bytes never proxy through the CP), retention, legal hold, and governance
 * delete.
 */
@RestController
public class RecordingController implements RecordingsApi {

	private final PlatformAccess access;

	public RecordingController(PlatformAccess access) {
		this.access = access;
	}

	@Override
	public Mono<ResponseEntity<RecordingPage>> listRecordings(String cursor, Integer limit, UUID sessionId,
			String identity, UUID nodeId, ServerWebExchange exchange) {
		return frozen(PlatformPermissions.RECORDING_REPLAY);
	}

	@Override
	public Mono<ResponseEntity<RecordingResource>> getRecording(UUID recordingId, ServerWebExchange exchange) {
		return frozen(PlatformPermissions.RECORDING_REPLAY);
	}

	@Override
	public Mono<ResponseEntity<SignedUrl>> replayRecording(UUID recordingId, String idempotencyKey,
			ServerWebExchange exchange) {
		return frozen(PlatformPermissions.RECORDING_REPLAY);
	}

	@Override
	public Mono<ResponseEntity<SignedUrl>> exportRecording(UUID recordingId, String idempotencyKey,
			ServerWebExchange exchange) {
		return frozen(PlatformPermissions.RECORDING_EXPORT);
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteRecording(UUID recordingId, String idempotencyKey,
			ServerWebExchange exchange) {
		return frozen(PlatformPermissions.RECORDING_DELETE);
	}

	@Override
	public Mono<ResponseEntity<RecordingResource>> setRecordingLegalHold(UUID recordingId,
			Mono<LegalHoldRequest> legalHoldRequest, String idempotencyKey, ServerWebExchange exchange) {
		return frozen(PlatformPermissions.RECORDING_DELETE);
	}

	private <T> Mono<ResponseEntity<T>> frozen(String permission) {
		return access.withPermission(permission,
				subject -> Mono.error(ApiProblemException.notImplemented("recordings")));
	}
}
