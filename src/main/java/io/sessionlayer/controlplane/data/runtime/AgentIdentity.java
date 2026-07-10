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
 * RUNTIME · {@code runtime.agent_identity} (Design §8). Per-node mTLS identity
 * <b>reference</b> + {@code generation} counter (§8.2). The {@code @Version}
 * column is the optimistic-concurrency guard against a renewal race regressing
 * {@code generation} (a DB trigger also rejects a decrease). At most one
 * {@code active} identity per node (partial unique index).
 */
@Table(schema = "runtime", name = "agent_identity")
public record AgentIdentity(@Id UUID id, UUID nodeId, String mtlsIdentityRef, String fingerprint, long generation,
		String joinMethod, String status, Instant issuedAt, Instant notAfter, String statusReason,
		String statusChangedBy, Instant statusChangedAt, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static AgentIdentity create(UUID nodeId, String mtlsIdentityRef, String fingerprint, long generation,
			String joinMethod, String status, Instant issuedAt, Instant notAfter) {
		// status-transition reason/actor (F-DM-15) default null; set on lock/revoke.
		return new AgentIdentity(Uuids.v7(), nodeId, mtlsIdentityRef, fingerprint, generation, joinMethod, status,
				issuedAt, notAfter, null, null, null, null, null, null);
	}
}
