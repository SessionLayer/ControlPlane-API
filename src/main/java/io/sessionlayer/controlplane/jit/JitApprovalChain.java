package io.sessionlayer.controlplane.jit;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Pure logic for the JIT approval chain (FR-ACC-3/4). The chain is an ordered
 * 0-3 array of {@code {kind: "email"|"oidc_group", value}} levels, snapshotted
 * onto the request at submit; {@code approvals} accumulates
 * {@code {approver, level, decision, reason, at}} entries. Levels are approved
 * in order — the next level to act is the count of accumulated approvals.
 *
 * <p>
 * Two hard invariants live here so no chain config, re-request, or delegation
 * can bypass them (FR-ACC-4): (1) an approver can NEVER be the requester
 * (self-approval impossible), checked before any level match; (2) an approver
 * may act at most once, so an N-level chain needs N DISTINCT non-requester
 * approvers.
 */
public final class JitApprovalChain {

	public static final String KIND_EMAIL = "email";
	public static final String KIND_OIDC_GROUP = "oidc_group";

	private JitApprovalChain() {
	}

	public record Level(String kind, String value) {
	}

	public static List<Level> levels(JsonNode chain) {
		List<Level> levels = new ArrayList<>();
		if (chain != null && chain.isArray()) {
			for (JsonNode element : chain) {
				levels.add(new Level(text(element, "kind"), text(element, "value")));
			}
		}
		return levels;
	}

	/** How many levels have an accepted approval so far (the next level index). */
	public static int approvedCount(JsonNode approvals) {
		int count = 0;
		if (approvals != null && approvals.isArray()) {
			for (JsonNode element : approvals) {
				if ("approve".equals(text(element, "decision"))) {
					count++;
				}
			}
		}
		return count;
	}

	/** Whether {@code approver} already recorded any decision on this request. */
	public static boolean hasActed(JsonNode approvals, String approver) {
		if (approvals != null && approvals.isArray()) {
			for (JsonNode element : approvals) {
				if (approver != null && approver.equals(text(element, "approver"))) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Whether {@code approverIdentity} (with its groups) satisfies {@code level}:
	 * an {@code email} level matches the identity exactly; an {@code oidc_group}
	 * level matches group membership.
	 */
	public static boolean matches(Level level, String approverIdentity, Collection<String> approverGroups) {
		if (level == null || level.value() == null) {
			return false;
		}
		if (KIND_EMAIL.equals(level.kind())) {
			return level.value().equals(approverIdentity);
		}
		if (KIND_OIDC_GROUP.equals(level.kind())) {
			return approverGroups != null && approverGroups.contains(level.value());
		}
		return false; // unknown level kind → fail closed (no one satisfies it)
	}

	/** Append one decision to the approvals array, returning a fresh array node. */
	public static ArrayNode append(ObjectMapper objectMapper, JsonNode approvals, String approver, int level,
			String decision, String reason, Instant at) {
		ArrayNode array = objectMapper.createArrayNode();
		if (approvals != null && approvals.isArray()) {
			approvals.forEach(array::add);
		}
		ObjectNode entry = objectMapper.createObjectNode();
		entry.put("approver", approver);
		entry.put("level", level);
		entry.put("decision", decision);
		if (reason != null) {
			entry.put("reason", reason);
		}
		entry.put("at", at.toString());
		array.add(entry);
		return array;
	}

	private static String text(JsonNode node, String field) {
		JsonNode value = node == null ? null : node.get(field);
		return value != null && value.isString() ? value.stringValue() : null;
	}
}
