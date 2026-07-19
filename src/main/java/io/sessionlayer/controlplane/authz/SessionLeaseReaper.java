package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Releases leaked FR-SESS-3 concurrency leases (F-reliability-lease-reaper-1).
 * A session that ends without a FinalizeRecording — a hard-killed Gateway is a
 * structural source (NFR-1) — never releases its {@code session_lease}. The
 * Authorize count already ignores it (the {@code expires_at} filter self-heals
 * correctness), but the {@code idx_session_lease_live} partial index
 * ({@code released_at IS NULL}) would otherwise retain it forever and slowly
 * bloat, so this sweep stamps {@code released_at} on any lease whose grant
 * window ended more than the grace ago — removing it from that index. Harmless
 * and idempotent (a still-live or already-released lease is never touched).
 *
 * <p>
 * Gated by {@code sessionlayer.session-limits.reaper.enabled} (default on). The
 * default interval is long enough not to fire during a short test (which drive
 * the sweep explicitly). It occupies a scheduling-pool thread for its run (the
 * pool is sized &ge; 2 in {@code application.properties}); failures are logged
 * and non-fatal (correctness never depends on this loop).
 */
@Component
@ConditionalOnProperty(value = "sessionlayer.session-limits.reaper.enabled", havingValue = "true", matchIfMissing = true)
public class SessionLeaseReaper {

	private static final Logger LOG = LoggerFactory.getLogger(SessionLeaseReaper.class);

	private final SessionLeaseRepository leases;
	private final SessionLimitProperties properties;
	private final SloMetrics metrics;

	public SessionLeaseReaper(SessionLeaseRepository leases, SessionLimitProperties properties, SloMetrics metrics) {
		this.leases = leases;
		this.properties = properties;
		this.metrics = metrics;
	}

	@Scheduled(fixedDelayString = "${sessionlayer.session-limits.reaper.interval:PT1H}", initialDelayString = "${sessionlayer.session-limits.reaper.interval:PT1H}")
	public void sweep() {
		Instant now = Instant.now();
		Instant cutoff = now.minus(properties.getReaper().getGrace());
		leases.reapExpired(now, cutoff).doOnNext(reaped -> {
			metrics.recordLeasesReaped(reaped);
			if (reaped > 0) {
				LOG.info("session-lease reaper released {} leaked (expired, unreleased) lease(s)", reaped);
			}
		}).onErrorResume(error -> {
			LOG.warn("session-lease reaper failed (the concurrency count already ignores expired leases): {}",
					error.toString());
			return Mono.empty();
		}).block();
	}
}
