package io.sessionlayer.controlplane.authz;

import java.util.Map;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/**
 * Matches an {@code access_lock.target_selector} against a connect (Design
 * §6.1/§8.4, FR-AUTHZ-4). A Lock is the top-tier un-overridable deny, so this
 * <b>fails closed</b>: an empty or uninterpretable target matches (a global
 * lockdown / a typo over-blocks rather than under-blocks — "deny wins"). A
 * recognized target matches if <b>any</b> of its facets matches the connect
 * ({@code identity}, {@code node_id}, {@code principal}, {@code node_label}).
 *
 * <p>
 * Two selector shapes are recognized (OR-matched, same semantics): the S5
 * singular form ({@code identity}, {@code group}, {@code node_id},
 * {@code principal}, {@code node_label{key,value}}) and the Session-Ten
 * lock-CRUD plural form mirroring the frozen {@code LockTarget} wire message
 * ({@code identities}, {@code groups}, {@code node_ids}, {@code principals},
 * {@code node_labels} as {@code "key=value"}, {@code all}). This is the SAME
 * matching the Gateway ports to Rust for its per-channel local checks.
 */
public final class LockMatching {

	private LockMatching() {
	}

	/**
	 * The connect facets a lock may target (§8.3: identity/role/login/node/…).
	 * {@code requestedPrincipal} is the login being attempted;
	 * {@code allowedLogins} lets a principal-lock also block a "what may I do"
	 * query that would resolve to the locked login; {@code groups} lets a lock
	 * target an SSO/OIDC group.
	 */
	public record LockSubject(String identity, String nodeId, Map<String, String> labels, Set<String> allowedLogins,
			String requestedPrincipal, Set<String> groups) {
	}

	public static boolean matches(JsonNode target, LockSubject subject) {
		if (target == null || !target.isObject() || target.isEmpty()) {
			return true; // uninterpretable/empty → fail closed (lock applies)
		}
		boolean recognized = false;

		// An explicit fleet-wide lock denies everything (§8.3 — never implicit; ingest
		// requires all:true for a target that carries no other facet).
		if (target.has("all")) {
			recognized = true;
			if (target.get("all").asBoolean(false)) {
				return true;
			}
		}
		if (target.has("identity")) {
			recognized = true;
			if (equalsNonNull(Selectors.text(target.get("identity")), subject.identity())) {
				return true;
			}
		}
		if (target.has("identities")) {
			recognized = true;
			if (containsText(target.get("identities"), subject.identity())) {
				return true;
			}
		}
		if (target.has("group")) {
			recognized = true;
			if (subject.groups().contains(Selectors.text(target.get("group")))) {
				return true;
			}
		}
		if (target.has("groups")) {
			recognized = true;
			if (anyIn(target.get("groups"), subject.groups())) {
				return true;
			}
		}
		if (target.has("node_id")) {
			recognized = true;
			if (equalsNonNull(Selectors.text(target.get("node_id")), subject.nodeId())) {
				return true;
			}
		}
		if (target.has("node_ids")) {
			recognized = true;
			if (containsText(target.get("node_ids"), subject.nodeId())) {
				return true;
			}
		}
		if (target.has("principal")) {
			recognized = true;
			if (principalLocked(Selectors.text(target.get("principal")), subject)) {
				return true;
			}
		}
		if (target.has("principals")) {
			recognized = true;
			if (anyPrincipalLocked(target.get("principals"), subject)) {
				return true;
			}
		}
		if (target.has("node_label")) {
			recognized = true;
			if (labelLocked(target.get("node_label"), subject.labels())) {
				return true;
			}
		}
		if (target.has("node_labels")) {
			recognized = true;
			if (anyLabelLocked(target.get("node_labels"), subject.labels())) {
				return true;
			}
		}
		// An object with no facet we understand could be meant to lock this connect;
		// fail closed rather than silently ignore it.
		return !recognized;
	}

	private static boolean principalLocked(String locked, LockSubject subject) {
		if (locked == null) {
			return false;
		}
		return locked.equals(subject.requestedPrincipal()) || subject.allowedLogins().contains(locked);
	}

	private static boolean anyPrincipalLocked(JsonNode array, LockSubject subject) {
		if (array == null || !array.isArray()) {
			return false;
		}
		for (JsonNode element : array) {
			if (principalLocked(Selectors.text(element), subject)) {
				return true;
			}
		}
		return false;
	}

	private static boolean labelLocked(JsonNode nodeLabel, Map<String, String> labels) {
		if (nodeLabel == null || !nodeLabel.isObject()) {
			return true; // malformed node_label facet → fail closed
		}
		String key = Selectors.text(nodeLabel.get("key"));
		String value = Selectors.text(nodeLabel.get("value"));
		if (key == null || value == null) {
			return true;
		}
		return value.equals(labels.get(key));
	}

	// node_labels are "key=value" strings (the wire/CRUD form). A "key=" with an
	// empty value matches a label whose value is empty; a token with no '=' is
	// uninterpretable → fail closed (over-block; ingest validation rejects it up
	// front, so this is defense in depth against a hand-inserted row).
	private static boolean anyLabelLocked(JsonNode array, Map<String, String> labels) {
		if (array == null || !array.isArray()) {
			return false;
		}
		for (JsonNode element : array) {
			String token = Selectors.text(element);
			if (token == null) {
				continue;
			}
			int eq = token.indexOf('=');
			if (eq < 0) {
				return true; // malformed "key=value" → fail closed
			}
			if (token.substring(eq + 1).equals(labels.get(token.substring(0, eq)))) {
				return true;
			}
		}
		return false;
	}

	private static boolean containsText(JsonNode array, String value) {
		if (value == null || array == null || !array.isArray()) {
			return false;
		}
		for (JsonNode element : array) {
			if (value.equals(Selectors.text(element))) {
				return true;
			}
		}
		return false;
	}

	private static boolean anyIn(JsonNode array, Set<String> values) {
		if (array == null || !array.isArray()) {
			return false;
		}
		for (JsonNode element : array) {
			if (values.contains(Selectors.text(element))) {
				return true;
			}
		}
		return false;
	}

	private static boolean equalsNonNull(String a, String b) {
		return a != null && a.equals(b);
	}
}
