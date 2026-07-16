package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.RecordingsApi;
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
 * Session-recording admin surface (Design §12.2). FROZEN CONTRACT: the routes
 * exist and are RBAC-gated so an unauthorized caller still gets {@code 403},
 * but every operation returns {@code 501} until Session 18 implements
 * replay/export signed-URL issuance (bytes never proxy through the CP).
 * Reads/replay need {@code recording:replay}; export needs
 * {@code recording:export}.
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

	// Gate on the permission first (an unauthorized caller still gets 403), then
	// fail with a 501 problem — the contract is frozen, the behaviour lands in S18.
	private <T> Mono<ResponseEntity<T>> frozen(String permission) {
		return access.withPermission(permission,
				subject -> Mono.error(ApiProblemException.notImplemented("recordings")));
	}
}
