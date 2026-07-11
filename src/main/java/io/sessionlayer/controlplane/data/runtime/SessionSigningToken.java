package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * RUNTIME · {@code runtime.session_signing_token} (Design §15 / FR-CA-3). The
 * single-use, CP-minted authority for one {@code SignSessionCertificate} call,
 * bound to {@code {gatewayId, sessionId, nodeId, principal, exp}}. mTLS
 * authenticates the calling Gateway; this token authorises <i>what</i> is
 * signed, so a Gateway can never obtain a certificate for a session it does not
 * own. Stores {@code tokenHash} only; the atomic single-use marker is
 * {@code used}. {@code gatewayId} is a runtime→runtime snapshot of the owning
 * {@code gateway_identity.id} (no FK). S5/S8 mint it from a real RBAC decision.
 */
@Table(schema = "runtime", name = "session_signing_token")
public record SessionSigningToken(@Id UUID id, String tokenHash, UUID gatewayId, UUID sessionId, UUID nodeId,
		String principal, List<String> capabilities, String sourceAddress, Instant expiresAt, boolean used,
		Instant usedAt, @Version Long version, @CreatedDate Instant createdAt) {

	public static SessionSigningToken create(String tokenHash, UUID gatewayId, UUID sessionId, UUID nodeId,
			String principal, List<String> capabilities, String sourceAddress, Instant expiresAt) {
		return new SessionSigningToken(Uuids.v7(), tokenHash, gatewayId, sessionId, nodeId, principal, capabilities,
				sourceAddress, expiresAt, false, null, null, null);
	}
}
