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
 * RUNTIME · {@code runtime.service_account_credential} (F-DM-12 / FR-AUTH-12).
 * An issued machine-consumer credential (rotatable, revocable).
 * {@code config.service_account} is the definition; this is the runtime
 * issuance. {@code serviceAccountId}/{@code serviceAccountName} are a snapshot
 * (no FK across runtime→config). {@code secretHash} is a hash / public-key
 * reference, never a raw secret. Behaviour (issuance/rotation) is S6.
 */
@Table(schema = "runtime", name = "service_account_credential")
public record ServiceAccountCredential(@Id UUID id, UUID serviceAccountId, String serviceAccountName,
		String credentialType, String secretHash, String fingerprint, String status, Instant issuedAt, Instant notAfter,
		Instant revokedAt, String revokedReason, String revokedBy, @Version Long version,
		@CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static ServiceAccountCredential create(UUID serviceAccountId, String serviceAccountName,
			String credentialType, String secretHash, String fingerprint, Instant issuedAt, Instant notAfter) {
		return new ServiceAccountCredential(Uuids.v7(), serviceAccountId, serviceAccountName, credentialType,
				secretHash, fingerprint, "active", issuedAt, notAfter, null, null, null, null, null, null);
	}

	public ServiceAccountCredential revoked(String reason, String by, Instant at) {
		return new ServiceAccountCredential(id, serviceAccountId, serviceAccountName, credentialType, secretHash,
				fingerprint, "revoked", issuedAt, notAfter, at, reason, by, version, createdAt, updatedAt);
	}

	public boolean usable(Instant now) {
		return "active".equals(status) && (notAfter == null || notAfter.isAfter(now));
	}
}
