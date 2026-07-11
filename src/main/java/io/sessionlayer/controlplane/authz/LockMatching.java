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
		if (target.has("identity")) {
			recognized = true;
			if (equalsNonNull(Selectors.text(target.get("identity")), subject.identity())) {
				return true;
			}
		}
		if (target.has("group")) {
			recognized = true;
			if (subject.groups().contains(Selectors.text(target.get("group")))) {
				return true;
			}
		}
		if (target.has("node_id")) {
			recognized = true;
			if (equalsNonNull(Selectors.text(target.get("node_id")), subject.nodeId())) {
				return true;
			}
		}
		if (target.has("principal")) {
			recognized = true;
			if (principalLocked(Selectors.text(target.get("principal")), subject)) {
				return true;
			}
		}
		if (target.has("node_label")) {
			recognized = true;
			if (labelLocked(target.get("node_label"), subject.labels())) {
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

	private static boolean equalsNonNull(String a, String b) {
		return a != null && a.equals(b);
	}
}
