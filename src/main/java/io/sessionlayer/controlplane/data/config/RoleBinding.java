package io.sessionlayer.controlplane.data.config;

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
 * CONFIG · {@code config.role_binding} (FR-PADM-2). Binds a subject
 * (user/group) to a {@link PlatformRole} ({@code roleId} is a config-&gt;config
 * FK), optionally scoped (node-label/user/time) for
 * {@code recording:replay/export}.
 */
@Table(schema = "config", name = "role_binding")
public record RoleBinding(@Id UUID id, UUID roleId, String subjectKind, String subject, JsonNode scope, String origin,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static RoleBinding create(UUID roleId, String subjectKind, String subject, JsonNode scope, String origin) {
		return new RoleBinding(Uuids.v7(), roleId, subjectKind, subject, scope, origin, null, null, null);
	}
}
