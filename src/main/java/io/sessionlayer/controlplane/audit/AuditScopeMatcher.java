package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformScope;
import io.sessionlayer.controlplane.platform.PlatformScopes;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import tools.jackson.databind.JsonNode;

/**
 * In-app equivalent of the {@link AuditSearchSql} scope predicate, for the
 * single-event {@code GET /v1/audit-events/{id}} path where there is no SQL
 * filter to lean on (FR-AUD-8, FR-PADM-2). A scoped {@code audit:read} caller
 * may read one event only if some grant covers it, mirroring
 * {@link PlatformScopes} facet semantics: node-label containment, actor-or-
 * subject user match, inclusive time window. Fail-closed — a malformed scope
 * covers nothing.
 */
public final class AuditScopeMatcher {

	private AuditScopeMatcher() {
	}

	/**
	 * Whether any scoped grant covers {@code event}. An empty list matches none.
	 */
	public static boolean inScope(AuditEvent event, List<JsonNode> scopes) {
		Map<String, String> labels = labels(event.nodeLabels());
		Instant at = event.occurredAt();
		for (JsonNode scope : scopes) {
			if (coversUser(scope, labels, at, event.actor()) || coversUser(scope, labels, at, event.subject())) {
				return true;
			}
		}
		return false;
	}

	// A users facet matches the event if EITHER actor or subject is in the set, so
	// covers() is tested for each (the node-label/time facets are identical either
	// way) — the same actor-OR-subject the SQL predicate applies.
	private static boolean coversUser(JsonNode scope, Map<String, String> labels, Instant at, String user) {
		try {
			return PlatformScopes.covers(scope, new PlatformScope(labels, user, at));
		} catch (RuntimeException failClosed) {
			return false;
		}
	}

	private static Map<String, String> labels(JsonNode node) {
		if (node == null || !node.isObject()) {
			return Map.of();
		}
		Map<String, String> map = new HashMap<>();
		for (var property : node.properties()) {
			if (property.getValue() != null && property.getValue().isString()) {
				map.put(property.getKey(), property.getValue().stringValue());
			}
		}
		return map;
	}
}
