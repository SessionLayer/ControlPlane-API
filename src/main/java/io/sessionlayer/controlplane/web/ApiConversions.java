package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.model.Capability;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.springframework.web.server.ServerWebExchange;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Small conversions between the generated API models and the R2DBC entities
 * used across the Session 17 config controllers: free-form {@code jsonb}
 * selectors ({@code Map<String,Object>} &lt;-&gt; {@link JsonNode}), capability
 * enums &lt;-&gt; {@code text[]}, and {@link Instant} &lt;-&gt;
 * {@link OffsetDateTime}.
 */
public final class ApiConversions {

	private ApiConversions() {
	}

	public static JsonNode toJson(ObjectMapper mapper, Map<String, Object> map) {
		return map == null ? mapper.createObjectNode() : mapper.valueToTree(map);
	}

	public static JsonNode toJsonOrNull(ObjectMapper mapper, Map<String, Object> map) {
		return map == null ? null : mapper.valueToTree(map);
	}

	@SuppressWarnings("unchecked")
	public static Map<String, Object> toMap(ObjectMapper mapper, JsonNode node) {
		return node == null || node.isNull() ? Map.of() : mapper.convertValue(node, Map.class);
	}

	public static List<String> capabilityValues(List<Capability> capabilities) {
		return capabilities == null ? List.of() : capabilities.stream().map(Capability::getValue).toList();
	}

	public static List<Capability> toCapabilities(List<String> values) {
		return values == null ? List.of() : values.stream().map(Capability::fromValue).toList();
	}

	public static OffsetDateTime toOffset(Instant instant) {
		return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
	}

	/** The request method + path, used to scope an {@code Idempotency-Key}. */
	public static String method(ServerWebExchange exchange) {
		return exchange.getRequest().getMethod().name();
	}

	public static String path(ServerWebExchange exchange) {
		return exchange.getRequest().getPath().value();
	}
}
