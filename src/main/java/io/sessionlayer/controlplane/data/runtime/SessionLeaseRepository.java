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
	 * Live-lease count for an identity = current concurrency (FR-SESS-3).
	 * Fleet-wide: every Gateway acquires its leases in this shared datastore, so
	 * the count spans the whole cluster. A lease counts only while it is BOTH
	 * unreleased AND unexpired ({@code expires_at} = the session's grant_expiry, at
	 * which the Gateway tears the session down): a crashed session that never
	 * released its lease stops counting once its grant window passes, so a leaked
	 * lease self-heals at grant_expiry and can never lock an identity out
	 * permanently — no reaper required for correctness.
	 */
	@Query("SELECT count(*) FROM runtime.session_lease WHERE identity = :identity AND released_at IS NULL "
			+ "AND (expires_at IS NULL OR expires_at > :now)")
	Mono<Long> countLiveByIdentity(String identity, Instant now);

	/**
	 * Release a session's live lease at teardown (idempotent — the
	 * {@code released_at
	 * IS NULL} guard makes a repeat release a no-op). Returns the rows affected.
	 */
	@Modifying
	@Query("UPDATE runtime.session_lease SET released_at = :now WHERE session_id = :sessionId AND released_at IS NULL")
	Mono<Integer> releaseBySessionId(UUID sessionId, Instant now);

	/**
	 * Re-stamp a live lease's expiry (S25 exact accounting — a RunToTtl session
	 * outliving grant_expiry keeps occupying its slot while the Gateway extends
	 * ahead of expiry). Guarded by {@code released_at IS NULL} so an ended/released
	 * lease is never resurrected, and {@code GREATEST} so a re-stamp can only
	 * extend, never shorten, the counted window (an accidental early call cannot
	 * under-count). A direct UPDATE (no {@code @Version} read-modify-write) so
	 * concurrent extends/releases never conflict. Returns the rows affected.
	 */
	@Modifying
	@Query("UPDATE runtime.session_lease SET expires_at = GREATEST(expires_at, :expiresAt) "
			+ "WHERE session_id = :sessionId AND released_at IS NULL")
	Mono<Integer> extendBySessionId(UUID sessionId, Instant expiresAt);

	/**
	 * Fleet-wide live (unreleased + unexpired) lease count — the
	 * {@code sessionlayer.session.lease.live} gauge (S25 Part D). No per-identity
	 * breakdown (OTEL content rule: enum-only tags).
	 */
	@Query("SELECT count(*) FROM runtime.session_lease WHERE released_at IS NULL "
			+ "AND (expires_at IS NULL OR expires_at > :now)")
	Mono<Long> countLive(Instant now);

	/**
	 * Reap leaked leases: mark released any lease still unreleased whose grant
	 * window ended before {@code cutoff} (a few minutes past its
	 * {@code expires_at}, for belt). A session that crashed without a
	 * FinalizeRecording (e.g. a hard-killed Gateway, NFR-1) never releases its
	 * lease; the count already ignores it (via the {@code expires_at} filter), but
	 * the {@code idx_session_lease_live} partial index (predicate
	 * {@code released_at IS NULL}) would otherwise keep it forever and bloat.
	 * Setting {@code released_at} removes it from that index. Idempotent and
	 * harmless — it never touches a still-live (unexpired) or already-released
	 * lease.
	 */
	@Modifying
	@Query("UPDATE runtime.session_lease SET released_at = :now "
			+ "WHERE released_at IS NULL AND expires_at IS NOT NULL AND expires_at < :cutoff")
	Mono<Integer> reapExpired(Instant now, Instant cutoff);
}
