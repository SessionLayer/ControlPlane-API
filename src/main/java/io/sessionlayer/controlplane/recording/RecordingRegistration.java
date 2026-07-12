package io.sessionlayer.controlplane.recording;

import java.util.UUID;

/**
 * The result of registering a recording at {@code BeginRecording}: the
 * recording id, the WORM object key the encrypted bytes must land at, the WORM
 * mode, and the customer key to seal the data key to. The upload credential is
 * issued separately (short-lived, at upload time) by {@code RequestUpload}. The
 * gRPC layer maps this onto {@code BeginRecordingResponse}.
 */
public record RecordingRegistration(UUID recordingId, String objectKey, String wormMode,
		CustomerKeyMaterial customerKey) {
}
