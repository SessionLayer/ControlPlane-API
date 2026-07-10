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
 * RUNTIME · {@code runtime.node} (Design §12A). Live node registration,
 * resolved labels, health/status, owning-gateway pointer.
 * {@code nodePolicyName} is a snapshot reference to
 * {@code config.node_policy.name} (no FK across the runtime→config boundary).
 */
@Table(schema = "runtime", name = "node")
public record Node(@Id UUID id, String name, String nodePolicyName, JsonNode resolvedLabels, String connectorKind,
		String status, String health, String owningGateway, String address, String statusReason, String statusChangedBy,
		Instant statusChangedAt, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static Node create(String name, String nodePolicyName, JsonNode resolvedLabels, String connectorKind,
			String status, String health, String owningGateway, String address) {
		// status-transition reason/actor (F-DM-15) default null; set on
		// quarantine/remove.
		return new Node(Uuids.v7(), name, nodePolicyName, resolvedLabels, connectorKind, status, health, owningGateway,
				address, null, null, null, null, null, null);
	}
}
