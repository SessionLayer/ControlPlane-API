package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

/**
 * Reactive repository for {@link AuditEvent} ({@code runtime.audit_event}).
 * Insert and read only — the table is append-only (a DB trigger rejects
 * UPDATE/DELETE), so callers MUST NOT invoke {@code save()} on an
 * already-persisted row nor any delete method. The finders back the FR-AUD-8/9
 * search + correlation paths.
 */
public interface AuditEventRepository extends ReactiveCrudRepository<AuditEvent, UUID> {

	Flux<AuditEvent> findByCorrelationId(UUID correlationId);

	Flux<AuditEvent> findByActor(String actor);

	Flux<AuditEvent> findBySessionId(UUID sessionId);

	/**
	 * The hash-chained rows in gapless {@code seq} order (the DB-assigned total
	 * order, V3/F-audit-chain-1). Filtered to rows that carry a {@code record_hash}
	 * (the S9-and-later chain) so a mix with any pre-chain history verifies
	 * cleanly. Backs the {@code AuditChainVerifier} tamper-evidence check
	 * (FR-AUD-3).
	 */
	@Query("SELECT * FROM runtime.audit_event WHERE record_hash IS NOT NULL ORDER BY seq")
	Flux<AuditEvent> findChainOrdered();
}
