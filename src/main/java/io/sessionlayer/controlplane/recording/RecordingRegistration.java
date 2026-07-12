package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.recording.WormObjectStore.PresignedUpload;
import java.util.UUID;

/**
 * The result of registering a recording at {@code BeginRecording}: the
 * recording id, the WORM object key the encrypted bytes must land at, the WORM
 * mode, the customer key to seal the data key to, and the short-lived
 * single-object upload credential. The gRPC layer maps this onto
 * {@code BeginRecordingResponse}.
 */
public record RecordingRegistration(UUID recordingId, String objectKey, String wormMode,
		CustomerKeyMaterial customerKey, PresignedUpload upload) {
}
