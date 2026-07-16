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
	 * Append one audit event carrying only the core dimensions. A convenience over
	 * {@link #record(AuditRecord)} for the ~40 config/login/lifecycle callers that
	 * have no connect-time snapshot dimensions to record; the five snapshot columns
	 * ({@code source_ip}/{@code access_model}/{@code capabilities}/
	 * {@code node_labels}/{@code correlation_id}) stay null. {@code detail} is a
	 * small, secret-free string map; {@code sessionId}/{@code nodeId} may be null.
	 */
	default Mono<Void> record(String actor, String subject, String action, String outcome, UUID sessionId, UUID nodeId,
			Map<String, String> detail) {
		return record(AuditRecord.of(actor, subject, action, outcome, sessionId, nodeId, detail));
	}

	/**
	 * Append one audit event with every FR-AUD-8/9 dimension the producer has
	 * (source IP, access model, capabilities, node labels, correlation id). This is
	 * the single append seam; the core {@link #record} overload delegates here with
	 * the snapshot dimensions null. The backing implementation is responsible for
	 * tamper-evidence (the Postgres impl hash-chains the whole row).
	 */
	Mono<Void> record(AuditRecord record);

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

	/**
	 * One audit append with the full FR-AUD-8/9 dimension set. {@code detail},
	 * {@code capabilities} and {@code nodeLabels} are defensively copied and may be
	 * null (a null column, not an empty one). {@code capabilities} MUST be the raw
	 * capability vocab and {@code sourceIp} a valid IP/CIDR literal — the producer
	 * validates before building, since a bad value would violate the column CHECK
	 * and roll back the enclosing transaction (e.g. an allow decision).
	 */
	record AuditRecord(String actor, String subject, String action, String outcome, UUID sessionId, UUID nodeId,
			Map<String, String> detail, String sourceIp, String accessModel, List<String> capabilities,
			Map<String, String> nodeLabels, UUID correlationId) {

		public AuditRecord {
			detail = (detail == null) ? null : Map.copyOf(detail);
			capabilities = (capabilities == null) ? null : List.copyOf(capabilities);
			nodeLabels = (nodeLabels == null) ? null : Map.copyOf(nodeLabels);
		}

		public static AuditRecord of(String actor, String subject, String action, String outcome, UUID sessionId,
				UUID nodeId, Map<String, String> detail) {
			return new AuditRecord(actor, subject, action, outcome, sessionId, nodeId, detail, null, null, null, null,
					null);
		}

		public static Builder builder(String actor, String subject, String action, String outcome) {
			return new Builder(actor, subject, action, outcome);
		}

		public static final class Builder {

			private final String actor;
			private final String subject;
			private final String action;
			private final String outcome;
			private UUID sessionId;
			private UUID nodeId;
			private Map<String, String> detail;
			private String sourceIp;
			private String accessModel;
			private List<String> capabilities;
			private Map<String, String> nodeLabels;
			private UUID correlationId;

			private Builder(String actor, String subject, String action, String outcome) {
				this.actor = actor;
				this.subject = subject;
				this.action = action;
				this.outcome = outcome;
			}

			public Builder session(UUID sessionId) {
				this.sessionId = sessionId;
				return this;
			}

			public Builder node(UUID nodeId) {
				this.nodeId = nodeId;
				return this;
			}

			public Builder detail(Map<String, String> detail) {
				this.detail = detail;
				return this;
			}

			public Builder sourceIp(String sourceIp) {
				this.sourceIp = sourceIp;
				return this;
			}

			public Builder accessModel(String accessModel) {
				this.accessModel = accessModel;
				return this;
			}

			public Builder capabilities(List<String> capabilities) {
				this.capabilities = capabilities;
				return this;
			}

			public Builder nodeLabels(Map<String, String> nodeLabels) {
				this.nodeLabels = nodeLabels;
				return this;
			}

			public Builder correlationId(UUID correlationId) {
				this.correlationId = correlationId;
				return this;
			}

			public AuditRecord build() {
				return new AuditRecord(actor, subject, action, outcome, sessionId, nodeId, detail, sourceIp,
						accessModel, capabilities, nodeLabels, correlationId);
			}
		}
	}

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
