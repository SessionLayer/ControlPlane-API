package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Refreshes the {@code sessionlayer.session.lease.live} gauge (S25 Part D) on a
 * light schedule — one fleet-wide count query, no per-identity breakdown (OTEL
 * content rule). Observability only: failures are logged and non-fatal, and
 * nothing reads the gauge for enforcement.
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
		leases.countLive(Instant.now()).doOnNext(metrics::updateLiveLeases).onErrorResume(error -> {
			LOG.warn("live-lease gauge refresh failed: {}", error.toString());
			return Mono.empty();
		}).block();
	}
}
