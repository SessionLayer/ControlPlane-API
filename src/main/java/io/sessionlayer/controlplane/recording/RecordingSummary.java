package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import java.time.Instant;
import java.util.UUID;

/**
 * A recording's admin-facing metadata (Design §12) — the {@code recording_ref}
 * provenance joined with its session's {@code identity}/{@code nodeId}/timing.
 * NEVER carries recording bytes or key material ({@code encryptionKeyRef} is a
 * reference, not the key). The controller maps this to the generated
 * {@code RecordingResource}.
 */
public record RecordingSummary(UUID id, UUID sessionId, String identity, UUID nodeId, String format, String status,
		String wormMode, Long sizeBytes, String hashChainHead, String encryptionKeyRef, boolean legalHold,
		Instant retentionUntil, Instant prunedAt, Instant startedAt, Instant endedAt, Instant createdAt) {

	static RecordingSummary of(RecordingRef ref, SshSession session) {
		return new RecordingSummary(ref.id(), ref.sessionId(), session == null ? null : session.identity(),
				session == null ? null : session.nodeId(), ref.format(), ref.status(), ref.wormMode(), ref.sizeBytes(),
				ref.hashChainHead(), ref.encryptionKeyRef(), ref.legalHold(), ref.retentionUntil(), ref.prunedAt(),
				session == null ? null : session.startedAt(), session == null ? null : session.endedAt(),
				ref.createdAt());
	}
}
