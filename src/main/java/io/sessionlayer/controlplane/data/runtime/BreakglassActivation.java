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
 * RUNTIME · {@code runtime.breakglass_activation} (FR-ACC-6). A break-glass
 * activation with mandatory post-hoc review. {@code breakglassPolicyId} is a
 * snapshot ref (no FK).
 */
@Table(schema = "runtime", name = "breakglass_activation")
public record BreakglassActivation(@Id UUID id, String principal, String reason, String alertRef,
		UUID breakglassPolicyId, String reviewStatus, String reviewer, Instant activatedAt, Instant reviewedAt,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static BreakglassActivation create(String principal, String reason, String alertRef, UUID breakglassPolicyId,
			String reviewStatus, Instant activatedAt) {
		return new BreakglassActivation(Uuids.v7(), principal, reason, alertRef, breakglassPolicyId, reviewStatus, null,
				activatedAt, null, null, null, null);
	}
}
