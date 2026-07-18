package io.sessionlayer.controlplane.data.runtime;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link SshSession} ({@code runtime.ssh_session}). */
public interface SshSessionRepository extends ReactiveCrudRepository<SshSession, UUID> {

	Flux<SshSession> findByIdentity(String identity);

	Flux<SshSession> findByNodeId(UUID nodeId);

	Flux<SshSession> findByAccessModel(String accessModel);

	/**
	 * Live-session count for an identity = the FR-SESS-3 per-identity concurrency
	 * (a session is live while it has not ended and its grant has not expired).
	 * HA-correct: every Gateway writes its session rows to this shared datastore,
	 * so the count spans the whole fleet — a per-Gateway count could not see
	 * sessions held by its peers.
	 */
	@Query("SELECT count(*) FROM runtime.ssh_session WHERE identity = :identity AND ended_at IS NULL "
			+ "AND grant_expiry > :now")
	Mono<Long> countActiveByIdentity(String identity, Instant now);
}
