package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.authz.SessionLeaseReaper;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * F-reliability-lease-reaper-1 — the leaked-lease sweep releases an
 * unreleased+expired (past the grace) lease so it drops out of the
 * {@code idx_session_lease_live} partial index, and leaves a still-live
 * (unexpired) lease and an already-released lease untouched.
 */
class SessionLeaseReaperIT extends AbstractMtlsIT {

	@Autowired
	private SessionLeaseRepository leases;
	@Autowired
	private SessionLeaseReaper reaper;

	@Test
	void theSweepReleasesLeakedExpiredLeasesAndLeavesTheRestUntouched() {
		String identity = "reap-" + UUID.randomUUID();
		// Leaked: unreleased, expired well past the default 5m grace.
		SessionLease leaked = leases.save(SessionLease.acquire(identity, null, "gw-x", Instant.now().minusSeconds(7200),
				Instant.now().minusSeconds(3600))).block();
		// Live: unreleased, grant window still in the future.
		SessionLease live = leases
				.save(SessionLease.acquire(identity, null, "gw-y", Instant.now(), Instant.now().plusSeconds(3600)))
				.block();
		// Already released (expired, but released_at is set).
		SessionLease released = leases.save(SessionLease.acquire(identity, null, "gw-z",
				Instant.now().minusSeconds(7200), Instant.now().minusSeconds(3600))).block();
		leases.save(new SessionLease(released.id(), released.identity(), released.sessionId(), released.gatewayName(),
				released.acquiredAt(), released.expiresAt(), Instant.now().minusSeconds(1800), released.version(),
				released.createdAt(), released.updatedAt())).block();
		Instant releasedAtBefore = leases.findById(released.id()).block().releasedAt();

		reaper.sweep();

		assertThat(leases.findById(leaked.id()).block().releasedAt()).isNotNull(); // reaped
		assertThat(leases.findById(live.id()).block().releasedAt()).isNull(); // untouched (still live)
		assertThat(leases.findById(released.id()).block().releasedAt()).isEqualTo(releasedAtBefore); // untouched
	}
}
