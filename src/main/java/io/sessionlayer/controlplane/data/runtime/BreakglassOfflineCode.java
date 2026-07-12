package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

/**
 * RUNTIME · {@code runtime.breakglass_offline_code} (FR-ACC-6). A pre-issued
 * single-use break-glass code — the IdP-independent fallback. Mirrors
 * {@link Otp}: stores {@code codeHash} only (the raw code is NEVER persisted),
 * ≥128-bit entropy, source-bound, atomic single-use via {@code used} under the
 * {@code @Version} lock. {@code revokedAt} lets an admin invalidate an unused
 * batch without a DELETE.
 */
@Table(schema = "runtime", name = "breakglass_offline_code")
public record BreakglassOfflineCode(@Id UUID id, String codeHash, String identity, List<String> allowedPrincipals,
		JsonNode nodeSelector, String sourceCidr, Instant expiresAt, boolean used, Instant usedAt, Instant revokedAt,
		String createdBy, @Version Long version, @CreatedDate Instant createdAt) {

	public static BreakglassOfflineCode issue(String codeHash, String identity, List<String> allowedPrincipals,
			JsonNode nodeSelector, String sourceCidr, Instant expiresAt, String createdBy) {
		return new BreakglassOfflineCode(Uuids.v7(), codeHash, identity, allowedPrincipals, nodeSelector, sourceCidr,
				expiresAt, false, null, null, createdBy, null, null);
	}
}
