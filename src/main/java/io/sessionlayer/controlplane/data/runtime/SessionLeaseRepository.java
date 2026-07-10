package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link SessionLease}. */
public interface SessionLeaseRepository extends ReactiveCrudRepository<SessionLease, UUID> {

	/**
	 * Live (unreleased) lease count for an identity = current concurrency
	 * (FR-SESS-3).
	 */
	@Query("SELECT count(*) FROM runtime.session_lease WHERE identity = :identity AND released_at IS NULL")
	Mono<Long> countLiveByIdentity(String identity);
}
