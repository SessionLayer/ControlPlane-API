package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Refreshes the {@code sessionlayer.session.lease.live} gauge (S25 Part D) on a
 * light schedule — one fleet-wide count query, no per-identity breakdown (OTEL
 * content rule). Observability only: failures are non-fatal and counted
 * ({@code sessionlayer.session.lease.live.refresh.failed}) so a silently-stale
 * gauge is detectable, and nothing reads the gauge for enforcement.
 *
 * <p>
 * Dashboard notes: the gauge reads 0 until the first refresh (~one interval
 * after boot), and EVERY CP instance reports the same fleet-wide count — a
 * scaled-out deployment must aggregate with max/last, never sum.
 */
@Component
public class SessionLeaseGaugeRefresher {

	private static final Logger LOG = LoggerFactory.getLogger(SessionLeaseGaugeRefresher.class);

	private final SessionLeaseRepository leases;
	private final SloMetrics metrics;

	public SessionLeaseGaugeRefresher(SessionLeaseRepository leases, SloMetrics metrics) {
		this.leases = leases;
		this.metrics = metrics;
	}

	@Scheduled(fixedDelayString = "${sessionlayer.session-limits.gauge-refresh:PT1M}", initialDelayString = "${sessionlayer.session-limits.gauge-refresh:PT1M}")
	public void refresh() {
		// Bounded block (the AuditPartitionMaintenance pattern): a wedged DB times
		// out instead of pinning a scheduling-pool thread and starving the other
		// jobs (the pool is shared by all six periodic jobs).
		try {
			leases.countLive(Instant.now()).doOnNext(metrics::updateLiveLeases)
					.onErrorResume(error -> refreshFailed(error.toString())).block(Duration.ofSeconds(30));
		} catch (RuntimeException blockTimeout) {
			refreshFailed(blockTimeout.toString());
		}
	}

	private Mono<Long> refreshFailed(String cause) {
		metrics.recordLeaseGaugeRefreshFailed();
		LOG.warn("live-lease gauge refresh failed (gauge is now stale): {}", cause);
		return Mono.empty();
	}
}
