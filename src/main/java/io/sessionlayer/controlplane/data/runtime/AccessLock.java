package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

/**
 * RUNTIME · {@code runtime.access_lock} — the Design §12A "lock" entity
 * (renamed; reserved word, §7.1). A Lock is the top-tier un-overridable deny
 * (Design §6.1/§8.4). <b>API-only</b> runtime resource: "deny now and keep it"
 * is a runtime Lock, never a config edit (FR-DATA-1). No {@code origin} column
 * — it is runtime state, not config.
 */
@Table(schema = "runtime", name = "access_lock")
public record AccessLock(@Id UUID id, JsonNode targetSelector, String mode, Integer ttlSeconds, Instant expiresAt,
		String reason, String createdBy, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static AccessLock create(JsonNode targetSelector, String mode, Integer ttlSeconds, Instant expiresAt,
			String reason, String createdBy) {
		return new AccessLock(Uuids.v7(), targetSelector, mode, ttlSeconds, expiresAt, reason, createdBy, null, null,
				null);
	}
}
