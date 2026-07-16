package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.audit.AuditEventStore.AuditPage;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * The FR-AUD-8/9 audit read path over the pluggable {@link AuditEventStore}
 * seam. Depends only on the interface (constructor-injected), so a SIEM/S3/
 * OpenSearch backend — or a test double — is swappable without touching this
 * class. It is read-only over existing rows; the only write it makes is the
 * FR-PADM-3 audit of the access itself (reading the audit trail is a gated
 * platform action, so each search/get appends one {@code audit.search}/
 * {@code audit.get} event).
 */
@Service
public class AuditEventSearchService {

	private final AuditEventStore store;

	public AuditEventSearchService(AuditEventStore store) {
		this.store = store;
	}

	/**
	 * Run the RBAC-scoped search, then audit the access. Auditing AFTER the query
	 * keeps a malformed request (e.g. a bad cursor, which errors on subscribe) from
	 * recording a served-search event, and keeps the returned page from including
	 * the very {@code audit.search} row it generated.
	 */
	public Mono<AuditPage> search(AuditQuery query, String actor) {
		return store.search(query)
				.flatMap(page -> auditAccess(actor, null, "audit.search", summarize(query)).thenReturn(page));
	}

	/**
	 * Audit the access up front, then load the event. Auditing first records the
	 * attempt even when the id is absent or out of the caller's scope (the
	 * controller resolves that into an indistinguishable 404) — an out-of-scope
	 * probe is exactly what an audit trail should capture.
	 */
	public Mono<AuditEvent> get(UUID id, String actor) {
		return auditAccess(actor, id.toString(), "audit.get", Map.of("audit_event_id", id.toString()))
				.then(store.findById(id));
	}

	private Mono<Void> auditAccess(String actor, String subject, String action, Map<String, String> detail) {
		return store.record(actor, subject, action, "success", null, null, detail);
	}

	// A compact, secret-free record of which filter dimensions were queried (values
	// are already caller-supplied filters, not sensitive derived data).
	private static Map<String, String> summarize(AuditQuery q) {
		Map<String, String> detail = new LinkedHashMap<>();
		put(detail, "actor", q.actor());
		put(detail, "subject", q.subject());
		put(detail, "action", q.action());
		put(detail, "outcome", q.outcome());
		put(detail, "session_id", q.sessionId());
		put(detail, "node_id", q.nodeId());
		put(detail, "source_ip", q.sourceIp());
		put(detail, "from", q.from());
		put(detail, "to", q.to());
		put(detail, "capability", q.capability());
		put(detail, "access_model", q.accessModel());
		put(detail, "correlation_id", q.correlationId());
		if (!q.nodeLabels().isEmpty()) {
			detail.put("node_labels", q.nodeLabels().toString());
		}
		detail.put("scoped", Boolean.toString(!q.scopeGrants().isEmpty()));
		return detail;
	}

	private static void put(Map<String, String> detail, String key, Object value) {
		if (value != null && !(value instanceof String s && s.isBlank())) {
			detail.put(key, value.toString());
		}
	}
}
