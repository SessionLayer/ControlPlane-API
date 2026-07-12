package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

/**
 * RUNTIME · {@code runtime.breakglass_credential} (FR-ACC-6, §5.2). A
 * registered break-glass FIDO2 {@code sk-ecdsa} PUBLIC key — the primary
 * IdP-independent path. Keyed by the OpenSSH SHA-256 fingerprint;
 * source-agnostic (a hardware token travels), scoped to
 * {@code allowedPrincipals} and an optional {@code nodeSelector}, revocable
 * ({@code revokedAt}) and optionally expiring. PUBLIC material only — no
 * private key is ever at rest.
 */
@Table(schema = "runtime", name = "breakglass_credential")
public record BreakglassCredential(@Id UUID id, String keyFingerprint, byte[] publicKey, String skApplication,
		String identity, List<String> allowedPrincipals, JsonNode nodeSelector, Instant expiresAt, Instant revokedAt,
		String createdBy, @Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static BreakglassCredential register(String keyFingerprint, byte[] publicKey, String skApplication,
			String identity, List<String> allowedPrincipals, JsonNode nodeSelector, Instant expiresAt,
			String createdBy) {
		return new BreakglassCredential(Uuids.v7(), keyFingerprint, publicKey, skApplication, identity,
				allowedPrincipals, nodeSelector, expiresAt, null, createdBy, null, null, null);
	}

	public BreakglassCredential revoked(Instant at) {
		return new BreakglassCredential(id, keyFingerprint, publicKey, skApplication, identity, allowedPrincipals,
				nodeSelector, expiresAt, at, createdBy, version, createdAt, updatedAt);
	}

	public boolean active(Instant now) {
		return revokedAt == null && (expiresAt == null || expiresAt.isAfter(now));
	}
}
