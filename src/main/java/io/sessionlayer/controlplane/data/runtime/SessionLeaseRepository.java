package io.sessionlayer.controlplane.data.runtime;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link SessionLease}. */
public interface SessionLeaseRepository extends ReactiveCrudRepository<SessionLease, UUID> {

	/**
	 * Live (unreleased) lease count for an identity = current concurrency
	 * (FR-SESS-3). Fleet-wide: every Gateway acquires its leases in this shared
	 * datastore, so the count spans the whole cluster.
	 */
	@Query("SELECT count(*) FROM runtime.session_lease WHERE identity = :identity AND released_at IS NULL")
	Mono<Long> countLiveByIdentity(String identity);

	/**
	 * Release a session's live lease at teardown (idempotent — the
	 * {@code released_at
	 * IS NULL} guard makes a repeat release a no-op). Returns the rows affected.
	 */
	@Modifying
	@Query("UPDATE runtime.session_lease SET released_at = :now WHERE session_id = :sessionId AND released_at IS NULL")
	Mono<Integer> releaseBySessionId(UUID sessionId, Instant now);
}
