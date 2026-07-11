package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Builders for {@code dp_rule}/{@code access_lock} selectors used by the authz
 * tests.
 */
final class AuthzFixtures {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	private AuthzFixtures() {
	}

	static ObjectNode identityAll() {
		return JSON.objectNode().put("all", true);
	}

	static ObjectNode identity(String... identities) {
		ObjectNode node = JSON.objectNode();
		node.set("identities", stringArray(identities));
		return node;
	}

	static ObjectNode groups(String... groups) {
		ObjectNode node = JSON.objectNode();
		node.set("groups", stringArray(groups));
		return node;
	}

	static ObjectNode labelEq(String key, String value) {
		ObjectNode condition = JSON.objectNode().put("op", "eq").put("value", value);
		return JSON.objectNode().set(key, condition);
	}

	static ObjectNode labelOp(String key, String op, String value) {
		ObjectNode condition = JSON.objectNode().put("op", op).put("value", value);
		return JSON.objectNode().set(key, condition);
	}

	static ObjectNode labelIn(String key, String... values) {
		ObjectNode condition = JSON.objectNode().put("op", "in");
		condition.set("values", stringArray(values));
		return JSON.objectNode().set(key, condition);
	}

	static ObjectNode sourceDeny(String... denyCidrs) {
		ObjectNode node = JSON.objectNode();
		node.set("deny_cidrs", stringArray(denyCidrs));
		return node;
	}

	static ObjectNode sourcePermit(String... permitCidrs) {
		ObjectNode node = JSON.objectNode();
		node.set("permit_cidrs", stringArray(permitCidrs));
		return node;
	}

	static ObjectNode lockIdentity(String identity) {
		return JSON.objectNode().put("identity", identity);
	}

	static ObjectNode lockNode(String nodeId) {
		return JSON.objectNode().put("node_id", nodeId);
	}

	static ObjectNode lockPrincipal(String principal) {
		return JSON.objectNode().put("principal", principal);
	}

	static ObjectNode lockGroup(String group) {
		return JSON.objectNode().put("group", group);
	}

	static DpRule sourceScopedDeny(String name, ObjectNode identitySelector, ObjectNode sourceIpCondition) {
		return DpRule.create(name, identitySelector, null, sourceIpCondition, List.of(), 0, List.of(), "deny", "api");
	}

	static DpRule allowForPrincipals(String name, ObjectNode identitySelector, List<String> principals,
			List<String> capabilities) {
		return DpRule.create(name, identitySelector, null, null, principals, 3600, capabilities, "allow", "api");
	}

	static ArrayNode stringArray(String... values) {
		ArrayNode array = JSON.arrayNode();
		for (String v : values) {
			array.add(v);
		}
		return array;
	}

	static DpRule allow(String name, ObjectNode identitySelector, List<String> principals, List<String> capabilities) {
		return DpRule.create(name, identitySelector, null, null, principals, 3600, capabilities, "allow", "api");
	}

	static DpRule deny(String name, ObjectNode identitySelector) {
		return DpRule.create(name, identitySelector, null, null, List.of(), 0, List.of(), "deny", "api");
	}

	static AccessLock lock(ObjectNode target) {
		return AccessLock.create(target, "strict", null, null, "incident", "tester");
	}

	static AuthorizationRequest request(String identity, Map<String, String> labels, String sourceIp,
			String requestedPrincipal) {
		return new AuthorizationRequest(identity, List.of(), java.util.UUID.randomUUID(), labels, sourceIp,
				requestedPrincipal);
	}

	static Instant now() {
		return Instant.parse("2026-07-11T00:00:00Z");
	}
}
