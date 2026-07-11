package io.sessionlayer.controlplane.platform;

import java.time.Instant;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/**
 * Decides whether a {@code role_binding}'s stored scope <b>covers</b> a
 * requested scopable action (FR-PADM-2). A binding with no scope is
 * unrestricted and covers anything; a scoped binding cannot authorize an
 * unscoped/global request. Each present facet ({@code node_labels},
 * {@code users}, {@code time}) must be satisfied (AND); an absent facet is
 * unrestricted. A malformed scope throws — the caller denies (fail closed).
 */
public final class PlatformScopes {

	private PlatformScopes() {
	}

	private static final Set<String> FACETS = Set.of("node_labels", "users", "time");

	public static boolean covers(JsonNode scope, PlatformScope request) {
		if (scope == null || scope.isNull() || scope.isEmpty()) {
			return true; // unrestricted binding (no scope)
		}
		// A malformed scope must fail closed, not silently widen the binding: a
		// non-object, or an object whose only keys are unrecognized (a typo'd facet),
		// covers nothing (mirrors LockMatching's recognized-facet discipline).
		if (!scope.isObject() || FACETS.stream().noneMatch(scope::has)) {
			return false;
		}
		if (request == null) {
			return false; // a scoped binding cannot authorize an unscoped/global action
		}
		return nodeLabelsCover(scope.get("node_labels"), request) && usersCover(scope.get("users"), request)
				&& timeCovers(scope.get("time"), request);
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
