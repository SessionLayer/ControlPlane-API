package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * RUNTIME · {@code runtime.recording_token} (Design §12/§15 / FR-AUD-1). The
 * single-use authority for one {@code Recording.BeginRecording} call, minted at
 * {@code Authorize} ALLOW alongside {@link SessionSigningToken} and bound to
 * the same {@code {gatewayId, sessionId, nodeId, principal, exp}}. mTLS
 * authenticates the calling Gateway; this token binds <i>which</i> session may
 * be recorded, so a Gateway can never register a recording for a session it
 * does not broker. Stores {@code tokenHash} only; the atomic single-use marker
 * is {@code used}.
 */
@Table(schema = "runtime", name = "recording_token")
public record RecordingToken(@Id UUID id, String tokenHash, UUID gatewayId, UUID sessionId, UUID nodeId,
		String principal, String sourceAddress, Instant expiresAt, boolean used, Instant usedAt, @Version Long version,
		@CreatedDate Instant createdAt) {

	public static RecordingToken create(String tokenHash, UUID gatewayId, UUID sessionId, UUID nodeId, String principal,
			String sourceAddress, Instant expiresAt) {
		return new RecordingToken(Uuids.v7(), tokenHash, gatewayId, sessionId, nodeId, principal, sourceAddress,
				expiresAt, false, null, null, null);
	}
}
