package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.time.Duration;
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
 * Reap-safety invariant (S25): a live RunToTtl session keeps its lease alive
 * via {@code ExtendSessionLease} (re-stamp to now + {@code lease-extension}),
 * so with a Gateway extending at half-window cadence a live lease is at least
 * {@code lease-extension/2 + reaper.grace} (defaults ⇒ ~12.5m) from being
 * reaped. The grace is therefore FLOORED at {@link #MIN_GRACE} — an operator
 * combo that shrank it toward zero would let this sweep reap a still-extending
 * live lease and silently under-count.
 *
 * <p>
 * Gated by {@code sessionlayer.session-limits.reaper.enabled} (default on). The
 * default interval is long enough not to fire during a short test (which drive
 * the sweep explicitly). Failures are logged and non-fatal (correctness never
 * depends on this loop), and the block is bounded so a wedged DB can never pin
 * a scheduling-pool thread.
 */
@Component
@ConditionalOnProperty(value = "sessionlayer.session-limits.reaper.enabled", havingValue = "true", matchIfMissing = true)
public class SessionLeaseReaper {

	static final Duration MIN_GRACE = Duration.ofMinutes(1);

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
		Instant cutoff = now.minus(effectiveGrace());
		try {
			leases.reapExpired(now, cutoff).doOnNext(reaped -> {
				metrics.recordLeasesReaped(reaped);
				if (reaped > 0) {
					LOG.info("session-lease reaper released {} leaked (expired, unreleased) lease(s)", reaped);
				}
			}).onErrorResume(error -> {
				LOG.warn("session-lease reaper failed (the concurrency count already ignores expired leases): {}",
						error.toString());
				return Mono.empty();
			}).block(Duration.ofSeconds(30));
		} catch (RuntimeException blockTimeout) {
			LOG.warn("session-lease reaper timed out (the concurrency count already ignores expired leases): {}",
					blockTimeout.toString());
		}
	}

	private Duration effectiveGrace() {
		Duration configured = properties.getReaper().getGrace();
		if (configured == null || configured.compareTo(MIN_GRACE) < 0) {
			LOG.warn(
					"sessionlayer.session-limits.reaper.grace={} is below the {} floor — clamping (a near-zero "
							+ "grace could reap a live RunToTtl lease between extensions and under-count)",
					configured, MIN_GRACE);
			return MIN_GRACE;
		}
		return configured;
	}
}
