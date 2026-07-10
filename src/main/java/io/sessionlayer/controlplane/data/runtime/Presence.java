package io.sessionlayer.controlplane.data.runtime;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * RUNTIME · {@code runtime.presence} (Design §10.2 / FR-HA-2). Which Gateway
 * owns a node, at what address, with a monotonic nonce — queried before
 * routing. Keyed by {@code nodeId} (1:1 with {@link Node}).
 */
@Table(schema = "runtime", name = "presence")
public record Presence(@Id UUID nodeId, String owningGateway, String gatewayAddr, long nonce, UUID nonceId,
		Instant lastSeen, @Version Long version, @LastModifiedDate Instant updatedAt) {

	public static Presence create(UUID nodeId, String owningGateway, String gatewayAddr, long nonce, UUID nonceId,
			Instant lastSeen) {
		return new Presence(nodeId, owningGateway, gatewayAddr, nonce, nonceId, lastSeen, null, null);
	}
}
