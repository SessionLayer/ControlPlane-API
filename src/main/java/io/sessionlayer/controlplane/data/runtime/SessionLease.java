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
 * RUNTIME · {@code runtime.session_lease} (F-DM-8 / FR-SESS-3). The durable
 * per-identity concurrency primitive: one live lease per active session, so
 * per-identity concurrency = count of unreleased leases. The enforcement
 * semaphore (lease acquire/release under the limit) is S7.
 */
@Table(schema = "runtime", name = "session_lease")
public record SessionLease(@Id UUID id, String identity, UUID sessionId, String gatewayName, Instant acquiredAt,
		Instant expiresAt, Instant releasedAt, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static SessionLease acquire(String identity, UUID sessionId, String gatewayName, Instant acquiredAt,
			Instant expiresAt) {
		return new SessionLease(Uuids.v7(), identity, sessionId, gatewayName, acquiredAt, expiresAt, null, null, null,
				null);
	}
}
