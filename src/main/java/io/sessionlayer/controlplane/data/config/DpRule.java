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
import tools.jackson.databind.JsonNode;

/**
 * CONFIG · {@code config.dp_rule} (Design §6.1 / FR-AUTHZ-1). A data-plane RBAC
 * grant as typed policy-as-data: identity × node-label × source-IP selectors
 * -&gt; principals, ttl, capability set, allow|deny. S5 evaluates; this session
 * only stores/round-trips. Lock is NOT here (it is runtime).
 */
@Table(schema = "config", name = "dp_rule")
public record DpRule(@Id UUID id, String name, JsonNode identitySelector, JsonNode nodeLabelSelector,
		JsonNode sourceIpCondition, List<String> principals, int ttlSeconds, List<String> capabilities, String effect,
		String origin, @Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static DpRule create(String name, JsonNode identitySelector, JsonNode nodeLabelSelector,
			JsonNode sourceIpCondition, List<String> principals, int ttlSeconds, List<String> capabilities,
			String effect, String origin) {
		return new DpRule(Uuids.v7(), name, identitySelector, nodeLabelSelector, sourceIpCondition, principals,
				ttlSeconds, capabilities, effect, origin, null, null, null);
	}
}
