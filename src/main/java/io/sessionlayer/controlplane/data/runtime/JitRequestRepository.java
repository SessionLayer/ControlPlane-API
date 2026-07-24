package io.sessionlayer.controlplane.data.runtime;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link JitRequest} ({@code runtime.jit_request}). */
public interface JitRequestRepository extends ReactiveCrudRepository<JitRequest, UUID> {

	Flux<JitRequest> findByState(String state);

	Flux<JitRequest> findByRequester(String requester);

	/**
	 * The usable grant for a connect (S30, Authorize's now-unconditional lookup): a
	 * point query on {@code idx_jit_request_usable} instead of a per-requester scan
	 * of every historical row. Deterministic — the earliest-expiring match.
	 */
	@Query("SELECT * FROM runtime.jit_request WHERE requester = :requester AND target_node_id = :nodeId "
			+ "AND principal = :principal AND state IN ('APPROVED', 'ACTIVE') AND grant_expires_at > :now "
			+ "ORDER BY grant_expires_at ASC LIMIT 1")
	Mono<JitRequest> findUsableGrant(String requester, UUID nodeId, String principal, Instant now);
}
