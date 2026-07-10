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
 * RUNTIME · {@code runtime.gateway_identity} (FR-BOOT-3). The Gateway's
 * CP-facing renewable mTLS identity + {@code generation} counter; a Gateway is
 * a first-class lockable principal.
 */
@Table(schema = "runtime", name = "gateway_identity")
public record GatewayIdentity(@Id UUID id, String name, String mtlsIdentityRef, String fingerprint, long generation,
		String joinMethod, String status, Instant issuedAt, Instant notAfter, String statusReason,
		String statusChangedBy, Instant statusChangedAt, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static GatewayIdentity create(String name, String mtlsIdentityRef, String fingerprint, long generation,
			String joinMethod, String status, Instant issuedAt, Instant notAfter) {
		// status-transition reason/actor (F-DM-15) default null; set on lock/revoke.
		return new GatewayIdentity(Uuids.v7(), name, mtlsIdentityRef, fingerprint, generation, joinMethod, status,
				issuedAt, notAfter, null, null, null, null, null, null);
	}
}
