package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * RUNTIME · {@code runtime.recording_ref} (FR-DATA-2 / FR-AUD-3). 1:1 with a
 * {@link SshSession} ({@code sessionId} is UNIQUE + FK).
 * {@code encryptionKeyRef} is a reference to the customer-held key, never key
 * material. {@code hashChainHead} is the recording hash-chain head (S9 fills).
 */
@Table(schema = "runtime", name = "recording_ref")
public record RecordingRef(@Id UUID id, UUID sessionId, String objectKey, String encryptionKeyRef, String hashChainHead,
		String wormMode, Long sizeBytes, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static RecordingRef create(UUID sessionId, String objectKey, String encryptionKeyRef, String hashChainHead,
			String wormMode, Long sizeBytes) {
		return new RecordingRef(Uuids.v7(), sessionId, objectKey, encryptionKeyRef, hashChainHead, wormMode, sizeBytes,
				null, null, null);
	}
}
