package io.sessionlayer.controlplane.authz;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/**
 * The typed matchers for the three data-plane grant selectors (FR-AUTHZ-1/2,
 * FR-AUTH-15). Each is a pure predicate over the stored {@code jsonb}. A
 * malformed selector throws — the evaluator turns any such error into a
 * fail-closed deny, so a bad rule can never widen access.
 *
 * <ul>
 * <li><b>identity</b> — {@code {identities:[...], groups:[...], all:bool}}; a
 * rule matches if the identity is listed, a group intersects, or {@code all}.
 * An absent/empty identity selector selects <b>no one</b> (a grant must name a
 * subject).</li>
 * <li><b>node label</b> — {@code {key: condition, ...}} where a condition is
 * {@code {op:eq|glob|in|regex, value|values}} or an array of them: <b>AND
 * across keys, OR within a key</b>. An absent selector matches all nodes; a key
 * whose label the node lacks fails that key.</li>
 * <li><b>source IP</b> — {@code {permit_cidrs:[...], deny_cidrs:[...]}}: a pure
 * reducer — it can only suppress a grant, never create one. An unknown source
 * IP with any restriction present fails closed.</li>
 * </ul>
 */
public final class Selectors {

	private Selectors() {
	}

	public static boolean identityMatches(JsonNode selector, String identity, Iterable<String> groups) {
		if (selector == null) {
			return false; // no subject named → selects no one
		}
		requireObject(selector, "identity_selector");
		JsonNode all = selector.get("all");
		if (all != null && all.isBoolean() && all.booleanValue()) {
			return true;
		}
		JsonNode identities = selector.get("identities");
		if (identity != null && identities != null && identities.isArray()) {
			for (JsonNode n : identities.values()) {
				if (identity.equals(text(n))) {
					return true;
				}
			}
		}
		JsonNode wantGroups = selector.get("groups");
		if (wantGroups != null && wantGroups.isArray()) {
			Set<String> want = new HashSet<>();
			for (JsonNode n : wantGroups.values()) {
				String t = text(n);
				if (t != null) {
					want.add(t);
				}
			}
			for (String g : groups) {
				if (want.contains(g)) {
					return true;
				}
			}
		}
		return false;
	}

	public static boolean labelMatches(JsonNode selector, Map<String, String> labels) {
		if (selector == null) {
			return true; // no node constraint → applies to all nodes
		}
		requireObject(selector, "node_label_selector");
		for (var entry : selector.properties()) {
			if (!keyMatches(entry.getValue(), labels.get(entry.getKey()))) {
				return false; // AND across keys
			}
		}
		return true;
	}

	private static boolean keyMatches(JsonNode condition, String labelValue) {
		if (condition.isArray()) {
			for (JsonNode c : condition.values()) {
				if (conditionMatches(c, labelValue)) {
					return true; // OR within a key
				}
			}
			return false;
		}
		return conditionMatches(condition, labelValue);
	}

	private static boolean conditionMatches(JsonNode condition, String labelValue) {
		requireObject(condition, "label condition");
		String op = text(condition.get("op"));
		if (op == null) {
			throw new IllegalArgumentException("label condition missing 'op'");
		}
		if (labelValue == null) {
			return false; // the node has no such label
		}
		return switch (op) {
			case "eq" -> labelValue.equals(requireValue(condition));
			case "glob" -> Globs.matches(requireValue(condition), labelValue);
			case "regex" -> AnchoredRe2.matches(requireValue(condition), labelValue);
			case "in" -> valuesOf(condition).contains(labelValue);
			default -> throw new IllegalArgumentException("unknown label op: " + op);
		};
	}

	public static boolean sourceIpPasses(JsonNode condition, String sourceIp) {
		if (condition == null) {
			return true; // no source restriction
		}
		requireObject(condition, "source_ip_condition");
		Set<String> permit = cidrs(condition.get("permit_cidrs"));
		Set<String> deny = cidrs(condition.get("deny_cidrs"));
		if (permit.isEmpty() && deny.isEmpty()) {
			return true;
		}
		// A restriction is present but we do not know the address → fail closed. This
		// is a reducer: without a confirmed in-range address the grant is suppressed,
		// never granted (FR-AUTH-15).
		if (sourceIp == null || sourceIp.isBlank() || !Cidrs.isAddress(sourceIp)) {
			return false;
		}
		if (!permit.isEmpty() && permit.stream().noneMatch(c -> Cidrs.contains(c, sourceIp))) {
			return false;
		}
		return deny.stream().noneMatch(c -> Cidrs.contains(c, sourceIp));
	}

	private static Set<String> cidrs(JsonNode array) {
		Set<String> out = new HashSet<>();
		if (array != null && array.isArray()) {
			for (JsonNode n : array.values()) {
				String t = text(n);
				if (t != null) {
					out.add(t);
				}
			}
		}
		return out;
	}

	private static Set<String> valuesOf(JsonNode condition) {
		JsonNode values = condition.get("values");
		if (values == null || !values.isArray()) {
			throw new IllegalArgumentException("'in' condition requires a 'values' array");
		}
		Set<String> out = new HashSet<>();
		for (JsonNode n : values.values()) {
			String t = text(n);
			if (t != null) {
				out.add(t);
			}
		}
		return out;
	}

	private static String requireValue(JsonNode condition) {
		String value = text(condition.get("value"));
		if (value == null) {
			throw new IllegalArgumentException("label condition requires a 'value'");
		}
		return value;
	}

	static String text(JsonNode node) {
		return node != null && node.isString() ? node.stringValue() : null;
	}

	private static void requireObject(JsonNode node, String what) {
		if (!node.isObject()) {
			throw new IllegalArgumentException(what + " must be a JSON object");
		}
	}
}
