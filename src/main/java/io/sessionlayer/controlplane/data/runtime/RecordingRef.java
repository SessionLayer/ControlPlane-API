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
 * RUNTIME · {@code runtime.recording_ref} (FR-DATA-2 / FR-AUD-3/6). 1:1 with a
 * {@link SshSession} ({@code sessionId} is UNIQUE + FK).
 * {@code encryptionKeyRef} is a reference to the customer-held key, never key
 * material. {@code hashChainHead} is the recording hash-chain head (S9 fills).
 * The retention/governance columns ({@code legalHold}, {@code prunedAt},
 * {@code deleteMode}, {@code deletedBy}) drive the S18 retention lifecycle: the
 * provenance row is retained even after the encrypted object is pruned/erased.
 */
@Table(schema = "runtime", name = "recording_ref")
public record RecordingRef(@Id UUID id, UUID sessionId, String objectKey, String encryptionKeyRef, String hashChainHead,
		String wormMode, Long sizeBytes, Instant retentionUntil, boolean legalHold, String status, String format,
		String contentDigest, String objectVersionId, Instant prunedAt, String deleteMode, String deletedBy,
		String legalHoldReason, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static RecordingRef create(UUID sessionId, String objectKey, String encryptionKeyRef, String hashChainHead,
			String wormMode, Long sizeBytes) {
		return new RecordingRef(Uuids.v7(), sessionId, objectKey, encryptionKeyRef, hashChainHead, wormMode, sizeBytes,
				null, false, "recording", "asciicast-v2", null, null, null, null, null, null, null, null, null);
	}

	/**
	 * Register a recording at {@code BeginRecording}: {@code id} is supplied by the
	 * caller (it is echoed as the recording id and embedded in {@code objectKey}),
	 * the WORM mode + retention window are the operator policy, and the integrity
	 * fields ({@code hashChainHead}/{@code contentDigest}/{@code objectVersionId})
	 * are filled write-once at finalize.
	 */
	public static RecordingRef begin(UUID id, UUID sessionId, String objectKey, String encryptionKeyRef,
			String wormMode, Instant retentionUntil) {
		return new RecordingRef(id, sessionId, objectKey, encryptionKeyRef, null, wormMode, null, retentionUntil, false,
				"recording", "asciicast-v2", null, null, null, null, null, null, null, null, null);
	}

	/**
	 * Commit the terminal integrity metadata at {@code FinalizeRecording}. The
	 * write-once provenance columns ({@code hashChainHead}/{@code contentDigest}/
	 * {@code objectVersionId}) go NULL→value (the DB trigger permits that once,
	 * then freezes them); {@code status} and {@code sizeBytes} are the mutable
	 * lifecycle fields. Null arguments leave the corresponding field unchanged (a
	 * FAILED recording has no object → no digest/version). {@code objectVersionId}
	 * is the object-store version id replay/export pins so a later shadow PUT can't
	 * be served (F-recording-worm-version-1 / §15).
	 */
	public RecordingRef finalized(String hashChainHead, String contentDigest, String objectVersionId, Long sizeBytes,
			String status) {
		return new RecordingRef(id, sessionId, objectKey, encryptionKeyRef,
				hashChainHead != null ? hashChainHead : this.hashChainHead, wormMode,
				sizeBytes != null ? sizeBytes : this.sizeBytes, retentionUntil, legalHold, status, format,
				contentDigest != null ? contentDigest : this.contentDigest,
				objectVersionId != null ? objectVersionId : this.objectVersionId, prunedAt, deleteMode, deletedBy,
				legalHoldReason, version, createdAt, updatedAt);
	}

	/**
	 * Place or release the legal hold (FR-AUD-6): blocks retention prune +
	 * governance delete.
	 */
	public RecordingRef withLegalHold(boolean held, String reason) {
		return new RecordingRef(id, sessionId, objectKey, encryptionKeyRef, hashChainHead, wormMode, sizeBytes,
				retentionUntil, held, status, format, contentDigest, objectVersionId, prunedAt, deleteMode, deletedBy,
				held ? reason : null, version, createdAt, updatedAt);
	}

	/**
	 * Mark the encrypted object deleted (retention prune or governance erasure);
	 * the row is retained.
	 */
	public RecordingRef pruned(String deleteMode, String deletedBy, Instant prunedAt) {
		return new RecordingRef(id, sessionId, objectKey, encryptionKeyRef, hashChainHead, wormMode, sizeBytes,
				retentionUntil, legalHold, status, format, contentDigest, objectVersionId, prunedAt, deleteMode,
				deletedBy, legalHoldReason, version, createdAt, updatedAt);
	}
}
