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
 * CONFIG · {@code config.node_policy} (Design §12A). Desired node labels,
 * connector kind, and declared host trust references. A config resource; carries
 * an {@code origin} provenance label.
 */
@Table(schema = "config", name = "node_policy")
public record NodePolicy(@Id UUID id, String name, JsonNode desiredLabels, String connectorKind, String hostPinRef,
		String hostCaRef, String origin, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static NodePolicy create(String name, JsonNode desiredLabels, String connectorKind, String hostPinRef,
			String hostCaRef, String origin) {
		return new NodePolicy(Uuids.v7(), name, desiredLabels, connectorKind, hostPinRef, hostCaRef, origin, null, null,
				null);
	}
}
