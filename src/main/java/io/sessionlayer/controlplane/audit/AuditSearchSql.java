package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Builds the parameterized keyset SQL for an audit-event search (FR-AUD-8/9).
 * Selects only {@code id} (the store re-loads full rows by id through the
 * mapped repository), newest-first, over {@code runtime.audit_event}. Every
 * value is a <b>bound parameter</b> — never string-concatenated — so no filter,
 * label, or scope value can inject SQL; only the (server-clamped, integer) page
 * size is inlined.
 *
 * <p>
 * The caller's RBAC {@code scopeGrants} are applied as an OR-group AND-ed with
 * the user filters, mirroring
 * {@link io.sessionlayer.controlplane.platform.PlatformScopes} facet semantics
 * (node-label containment, actor-or-subject user match, inclusive time window).
 * An empty grant list is unrestricted; a scoped grant with no
 * recognized/parseable facet matches nothing (fail closed).
 */
final class AuditSearchSql {

	private AuditSearchSql() {
	}

	record Built(String sql, Map<String, Object> params) {
	}

	static Built build(AuditQuery q, UUID afterId, int limitPlusOne, ObjectMapper objectMapper) {
		List<String> where = new ArrayList<>();
		Map<String, Object> params = new LinkedHashMap<>();

		if (afterId != null) {
			where.add("id < :cursor_id");
			params.put("cursor_id", afterId);
		}
		eq(where, params, "actor", q.actor());
		eq(where, params, "subject", q.subject());
		eq(where, params, "action", q.action());
		eq(where, params, "outcome", q.outcome());
		eq(where, params, "session_id", q.sessionId());
		eq(where, params, "node_id", q.nodeId());
		eq(where, params, "source_ip", q.sourceIp());
		eq(where, params, "correlation_id", q.correlationId());
		eq(where, params, "access_model", q.accessModel());
		if (q.from() != null) {
			where.add("occurred_at >= :from_ts");
			params.put("from_ts", q.from());
		}
		if (q.to() != null) {
			where.add("occurred_at < :to_ts");
			params.put("to_ts", q.to());
		}
		if (q.capability() != null && !q.capability().isBlank()) {
			where.add("capabilities @> ARRAY[:capability]::text[]");
			params.put("capability", q.capability());
		}
		if (!q.nodeLabels().isEmpty()) {
			where.add("node_labels @> :node_labels::jsonb");
			params.put("node_labels", objectMapper.writeValueAsString(q.nodeLabels()));
		}
		scope(where, params, q.scopeGrants());

		String sql = "SELECT id FROM runtime.audit_event"
				+ (where.isEmpty() ? "" : " WHERE " + String.join(" AND ", where)) + " ORDER BY id DESC LIMIT "
				+ limitPlusOne;
		return new Built(sql, params);
	}

	private static void eq(List<String> where, Map<String, Object> params, String column, Object value) {
		if (value == null || (value instanceof String s && s.isBlank())) {
			return;
		}
		where.add(column + " = :" + column);
		params.put(column, value);
	}

	// scopeGrants OR-ed and AND-ed with the user filters; empty => unrestricted.
	private static void scope(List<String> where, Map<String, Object> params, List<JsonNode> grants) {
		if (grants.isEmpty()) {
			return;
		}
		List<String> ors = new ArrayList<>();
		for (int i = 0; i < grants.size(); i++) {
			ors.add(grantPredicate(grants.get(i), i, params));
		}
		where.add("(" + String.join(" OR ", ors) + ")");
	}

	private static String grantPredicate(JsonNode grant, int i, Map<String, Object> params) {
		if (grant == null || !grant.isObject()) {
			return "(false)";
		}
		List<String> ands = new ArrayList<>();
		JsonNode labels = grant.get("node_labels");
		if (labels != null && labels.isObject() && !labels.isEmpty()) {
			String p = "g" + i + "_labels";
			ands.add("node_labels @> :" + p + "::jsonb");
			params.put(p, labels.toString());
		}
		JsonNode users = grant.get("users");
		if (users != null && users.isArray()) {
			List<String> names = new ArrayList<>();
			int u = 0;
			for (JsonNode user : users) {
				if (user.isString()) {
					String p = "g" + i + "_u" + u++;
					names.add(":" + p);
					params.put(p, user.stringValue());
				}
			}
			if (names.isEmpty()) {
				return "(false)"; // a present-but-empty user scope covers nothing
			}
			String in = String.join(",", names);
			ands.add("(actor IN (" + in + ") OR subject IN (" + in + "))");
		}
		JsonNode time = grant.get("time");
		if (time != null && time.isObject()) {
			try {
				String nb = text(time.get("not_before"));
				String na = text(time.get("not_after"));
				if (nb != null) {
					String p = "g" + i + "_nb";
					ands.add("occurred_at >= :" + p);
					params.put(p, Instant.parse(nb));
				}
				if (na != null) {
					String p = "g" + i + "_na";
					ands.add("occurred_at <= :" + p);
					params.put(p, Instant.parse(na));
				}
			} catch (RuntimeException malformed) {
				return "(false)"; // unparseable window => fail closed
			}
		}
		return ands.isEmpty() ? "(false)" : "(" + String.join(" AND ", ands) + ")";
	}

	private static String text(JsonNode node) {
		return node != null && node.isString() ? node.stringValue() : null;
	}
}
