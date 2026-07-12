package io.sessionlayer.controlplane.recording;

import java.util.UUID;

/**
 * The advisory, NON-authoritative context a {@code BeginRecording} caller may
 * echo for correlation. The single-use recording token is authoritative for
 * {@code {session, node, principal}}; a field set here is checked only when
 * present and, when present, MUST equal the token's bound value (a disagreement
 * fails closed). Mirrors the {@code SignRequestContext} pattern used by session
 * signing.
 */
public record RecordingRequestContext(UUID sessionId, UUID nodeId, String principal) {

	public static final RecordingRequestContext EMPTY = new RecordingRequestContext(null, null, null);
}
