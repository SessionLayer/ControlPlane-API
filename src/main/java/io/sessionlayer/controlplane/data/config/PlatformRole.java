package io.sessionlayer.controlplane.data.config;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * CONFIG · {@code config.platform_role} (FR-PADM-1). A named set of granular
 * platform permissions (permission vocabulary is CHECK-constrained in the
 * schema).
 */
@Table(schema = "config", name = "platform_role")
public record PlatformRole(@Id UUID id, String name, List<String> permissions, String description, String origin,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static PlatformRole create(String name, List<String> permissions, String description, String origin) {
		return new PlatformRole(Uuids.v7(), name, permissions, description, origin, null, null, null);
	}
}
