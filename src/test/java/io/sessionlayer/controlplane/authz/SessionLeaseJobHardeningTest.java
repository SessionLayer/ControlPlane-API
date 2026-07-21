package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import reactor.core.publisher.Mono;

/**
 * S25 F4/F5 hardening of the lease jobs: a failed gauge refresh is counted
 * (never a silently-stale gauge) and never throws out of the scheduler; the
 * reaper floors a dangerously-small grace so no operator combo can reap a
 * still-extending live RunToTtl lease (reap-safety invariant).
 */
class SessionLeaseJobHardeningTest {

	@Test
	void aFailedGaugeRefreshCountsAndKeepsTheLastValue() {
		SessionLeaseRepository leases = mock(SessionLeaseRepository.class);
		SimpleMeterRegistry registry = new SimpleMeterRegistry();
		SloMetrics metrics = new SloMetrics(registry);
		when(leases.countLive(any(Instant.class))).thenReturn(Mono.just(7L))
				.thenReturn(Mono.error(new IllegalStateException("db down")));
		SessionLeaseGaugeRefresher refresher = new SessionLeaseGaugeRefresher(leases, metrics);

		refresher.refresh();
		assertThat(registry.find("sessionlayer.session.lease.live").gauge().value()).isEqualTo(7.0);
		assertThat(refreshFailures(registry)).isZero();

		refresher.refresh(); // fails — counted, non-fatal, gauge keeps the last value
		assertThat(refreshFailures(registry)).isEqualTo(1.0);
		assertThat(registry.find("sessionlayer.session.lease.live").gauge().value()).isEqualTo(7.0);
	}

	@Test
	void theReaperFloorsABelowMinimumGrace() {
		assertThat(sweepGrace(Duration.ZERO)).isEqualTo(SessionLeaseReaper.MIN_GRACE);
	}

	@Test
	void theReaperKeepsAnOperatorGraceAboveTheFloor() {
		assertThat(sweepGrace(Duration.ofMinutes(5))).isEqualTo(Duration.ofMinutes(5));
	}

	// Drive one sweep with the given configured grace and return the grace the
	// reap query actually used (now - cutoff).
	private static Duration sweepGrace(Duration configured) {
		SessionLeaseRepository leases = mock(SessionLeaseRepository.class);
		SessionLimitProperties properties = new SessionLimitProperties();
		properties.getReaper().setGrace(configured);
		when(leases.reapExpired(any(Instant.class), any(Instant.class))).thenReturn(Mono.just(0));

		new SessionLeaseReaper(leases, properties, new SloMetrics(new SimpleMeterRegistry())).sweep();

		ArgumentCaptor<Instant> now = ArgumentCaptor.forClass(Instant.class);
		ArgumentCaptor<Instant> cutoff = ArgumentCaptor.forClass(Instant.class);
		verify(leases).reapExpired(now.capture(), cutoff.capture());
		return Duration.between(cutoff.getValue(), now.getValue());
	}

	private static double refreshFailures(SimpleMeterRegistry registry) {
		Counter counter = registry.find("sessionlayer.session.lease.live.refresh.failed").counter();
		return counter == null ? 0 : counter.count();
	}
}
