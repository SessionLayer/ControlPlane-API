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
 * RUNTIME · {@code runtime.oidc_login} (FR-AUTH-6). Transient auth-code + PKCE
 * relying-party state for one browser login. Stores the SHA-256 of the opaque
 * {@code state} only (single-use lookup); the PKCE verifier and the OIDC nonce
 * are <b>derived</b> server-side from the raw {@code state} and never
 * persisted. {@code purpose='device'} links a {@link DeviceFlow} that this
 * login approves (§5.2 anti-phishing). Single-use via {@code consumedAt}.
 */
@Table(schema = "runtime", name = "oidc_login")
public record OidcLogin(@Id UUID id, String stateHash, String purpose, UUID deviceFlowId, String sourceIp,
		String status, String resolvedIdentity, Instant expiresAt, Instant consumedAt, @Version Long version,
		@CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static OidcLogin create(String stateHash, String purpose, UUID deviceFlowId, String sourceIp,
			Instant expiresAt) {
		return new OidcLogin(Uuids.v7(), stateHash, purpose, deviceFlowId, sourceIp, "pending", null, expiresAt, null,
				null, null, null);
	}

	public OidcLogin consumed(String outcome, String resolvedIdentity, Instant at) {
		return new OidcLogin(id, stateHash, purpose, deviceFlowId, sourceIp, outcome, resolvedIdentity, expiresAt, at,
				version, createdAt, updatedAt);
	}
}
