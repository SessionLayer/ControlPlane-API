package io.sessionlayer.controlplane.platform;

import java.time.Instant;
import tools.jackson.databind.JsonNode;

/**
 * Decides whether a {@code role_binding}'s stored scope <b>covers</b> a
 * requested scopable action (FR-PADM-2). A binding with no scope is
 * unrestricted and covers anything; a scoped binding cannot authorize an
 * unscoped/global request, and must impose at least one <b>effective</b> facet
 * ({@code node_labels}, {@code users}, {@code time}) — each present-and-effective
 * facet must be satisfied (AND). A present-but-degenerate or unrecognized-only
 * scope imposes no constraint and therefore covers <b>nothing</b> (fail closed),
 * exactly mirroring {@code AuditSearchSql}'s scope predicate so the search filter
 * and the single-event scope check cannot diverge.
 */
public final class PlatformScopes {

	private PlatformScopes() {
	}

	public static boolean covers(JsonNode scope, PlatformScope request) {
		if (scope == null || scope.isNull() || scope.isEmpty()) {
			return true; // unrestricted binding (no scope)
		}
		if (!scope.isObject() || request == null) {
			// Non-object => malformed; a scoped binding cannot authorize an unscoped/global
			// action. Fail closed either way.
			return false;
		}
		// A scoped binding must impose at least one EFFECTIVE recognized facet, and cover
		// the request on each present-and-effective facet. A present-but-degenerate facet
		// (empty node_labels object, empty users array, a non-object/non-array facet, a
		// time object with no bounds, or only unrecognized keys) imposes NO constraint —
		// so a binding with no effective constraint covers NOTHING (fail closed). This
		// mirrors AuditSearchSql's non-empty-AND predicate exactly, so the search filter
		// and the single-event scope check can never diverge (no read-by-id scope bypass).
		boolean anyConstraint = false;
		JsonNode nodeLabels = scope.get("node_labels");
		if (nodeLabels != null && nodeLabels.isObject() && !nodeLabels.isEmpty()) {
			anyConstraint = true;
			if (!nodeLabelsCover(nodeLabels, request)) {
				return false;
			}
		}
		JsonNode users = scope.get("users");
		if (users != null && users.isArray() && !users.isEmpty()) {
			anyConstraint = true;
			if (!usersCover(users, request)) {
				return false;
			}
		}
		JsonNode time = scope.get("time");
		if (time != null && time.isObject() && (time.has("not_before") || time.has("not_after"))) {
			anyConstraint = true;
			if (!timeCovers(time, request)) {
				return false;
			}
		}
		return anyConstraint;
	}

	/**
	 * Whether a {@code role_binding} scope is storable: unset/empty (an unscoped
	 * binding) or imposing at least one <b>effective</b> facet. A degenerate or
	 * unrecognized-only scope ({@code {"node_labels":{}}}, {@code {"users":[]}}, a
	 * typo'd key) is rejected at write time — otherwise it covers nothing (fail
	 * closed) yet reads as "scoped", a footgun that silently locks a grant out.
	 */
	public static boolean isValid(JsonNode scope) {
		if (scope == null || scope.isNull() || scope.isEmpty()) {
			return true;
		}
		if (!scope.isObject()) {
			return false;
		}
		JsonNode nodeLabels = scope.get("node_labels");
		if (nodeLabels != null && nodeLabels.isObject() && !nodeLabels.isEmpty()) {
			return true;
		}
		JsonNode users = scope.get("users");
		if (users != null && users.isArray() && !users.isEmpty()) {
			return true;
		}
		JsonNode time = scope.get("time");
		return time != null && time.isObject() && (time.has("not_before") || time.has("not_after"));
	}

	private static boolean nodeLabelsCover(JsonNode nodeLabels, PlatformScope request) {
		if (nodeLabels == null || !nodeLabels.isObject()) {
			return true;
		}
		for (var entry : nodeLabels.properties()) {
			String want = text(entry.getValue());
			if (want == null || !want.equals(request.nodeLabels().get(entry.getKey()))) {
				return false;
			}
		}
		return true;
	}

	private static boolean usersCover(JsonNode users, PlatformScope request) {
		if (users == null || !users.isArray()) {
			return true;
		}
		for (JsonNode u : users.values()) {
			if (u.isString() && u.stringValue().equals(request.user())) {
				return true;
			}
		}
		return false;
	}

	private static boolean timeCovers(JsonNode time, PlatformScope request) {
		if (time == null || !time.isObject()) {
			return true;
		}
		Instant at = request.at();
		if (at == null) {
			return false; // a time-windowed binding cannot cover an unspecified time
		}
		String notBefore = text(time.get("not_before"));
		String notAfter = text(time.get("not_after"));
		if (notBefore != null && at.isBefore(Instant.parse(notBefore))) {
			return false;
		}
		return notAfter == null || !at.isAfter(Instant.parse(notAfter));
	}

	private static String text(JsonNode node) {
		return node != null && node.isString() ? node.stringValue() : null;
	}
}
