package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

/**
 * The pluggable audit-event store seam (owner requirement, §12.2/§15). The
 * correlated append-only audit stream is written and searched only through this
 * interface, so the current Postgres+hash-chain backend
 * ({@link PostgresAuditEventStore}) can be swapped for another (SIEM / S3 /
 * OpenSearch / syslog) without touching the rest of the CP. Shipping events
 * <b>off-box</b> to external systems is a separate seam
 * ({@link AuditForwarder}).
 *
 * <p>
 * The store is <b>append + read</b> only — never update/delete (the stream is
 * append-only and tamper-evident, FR-AUD-3); a {@link #search} or
 * {@link #findById} MUST NOT mutate it and MUST leave the chain verifiable
 * ({@link #verifyChain}).
 */
public interface AuditEventStore {

	/**
	 * Append one audit event. {@code detail} is a small, secret-free string map;
	 * {@code sessionId}/{@code nodeId} may be null. The backing implementation is
	 * responsible for tamper-evidence (the Postgres impl hash-chains).
	 */
	Mono<Void> record(String actor, String subject, String action, String outcome, UUID sessionId, UUID nodeId,
			Map<String, String> detail);

	/**
	 * Append a config-change event capturing before/after state (FR-PADM-3). The
	 * two objects MUST be secret-free (config exposes references, never key
	 * material).
	 */
	Mono<Void> recordChange(String actor, String subject, String action, Map<String, String> detail, Object before,
			Object after);

	/**
	 * Search the stream (FR-AUD-8/9); newest-first, cursor-paginated, read-only.
	 */
	Mono<AuditPage> search(AuditQuery query);

	/** One event by id (read-only), or empty if absent. */
	Mono<AuditEvent> findById(UUID id);

	/**
	 * Recompute + verify the tamper-evidence hash chain (FR-AUD-3). A read path
	 * calls this to prove a search left the chain intact.
	 */
	Mono<AuditChainVerifier.Result> verifyChain();

	/** A page of results plus the opaque forward cursor for the next page. */
	record AuditPage(List<AuditEvent> items, String nextCursor) {
	}

	/**
	 * A resolved audit-search query: the caller-supplied filter dimensions
	 * (FR-AUD-8) plus the RBAC {@code scopeGrants} the search must be confined to
	 * and the keyset {@code cursor}/{@code limit}. A null/blank filter is
	 * unrestricted for that dimension.
	 *
	 * @param nodeLabels
	 *            snapshot node labels that must all be present (AND)
	 * @param scopeGrants
	 *            the caller's scoped {@code audit:read} grants (each a
	 *            {@code role_binding.scope} object) OR-ed together; <b>empty means
	 *            unrestricted</b> (the caller holds an unscoped grant) — the
	 *            controller must have already denied a caller with no grant at all
	 */
	record AuditQuery(String actor, String subject, String action, String outcome, UUID sessionId, UUID nodeId,
			String sourceIp, Instant from, Instant to, String capability, String accessModel,
			Map<String, String> nodeLabels, UUID correlationId, List<JsonNode> scopeGrants, String cursor, int limit) {

		public AuditQuery {
			nodeLabels = (nodeLabels == null) ? Map.of() : Map.copyOf(nodeLabels);
			scopeGrants = (scopeGrants == null) ? List.of() : List.copyOf(scopeGrants);
		}
	}
}
