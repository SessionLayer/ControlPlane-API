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
 * CONFIG · {@code config.jit_policy} (FR-ACC-3). What is JIT-requestable plus
 * the 0–3 level approval chain ({@code approvalChain} is a jsonb array, length
 * CHECK ≤ 3, each level an email or OIDC group).
 */
@Table(schema = "config", name = "jit_policy")
public record JitPolicy(@Id UUID id, String name, JsonNode targetSelector, List<String> capabilities, int maxTtlSeconds,
		JsonNode approvalChain, String origin, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static JitPolicy create(String name, JsonNode targetSelector, List<String> capabilities, int maxTtlSeconds,
			JsonNode approvalChain, String origin) {
		return new JitPolicy(Uuids.v7(), name, targetSelector, capabilities, maxTtlSeconds, approvalChain, origin, null,
				null, null);
	}
}
