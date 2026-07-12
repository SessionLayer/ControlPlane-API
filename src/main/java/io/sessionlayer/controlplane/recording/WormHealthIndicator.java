package io.sessionlayer.controlplane.recording;

import java.time.Duration;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Readiness for the WORM recording store: recording is mandatory (FR-AUD-1/2),
 * so a CP that cannot reach the object store must stop taking new work — it is
 * wired into the <b>readiness</b> group (see {@code application.properties}),
 * so a down store drops the CP out of the LB rather than accepting sessions it
 * cannot record. The probe (HEAD bucket) is <b>cached</b> for a short TTL so
 * the health endpoint never hammers the store. Detail is not exposed
 * ({@code show-details=never}).
 *
 * <p>
 * Gated by {@code sessionlayer.recording.worm.readiness-gate} (default on).
 * When off, the indicator always reads UP — a deliberate escape hatch, because
 * gating couples the whole CP's availability (auth/CA/RBAC too) to the
 * recording store; an operator who would rather fail
 * BeginRecording/RequestUpload loudly (which the service already does) than
 * pull the whole CP from the LB can disable it. The bean is always registered
 * (so the readiness-group include stays valid); only its verdict changes.
 */
@Component("worm")
public class WormHealthIndicator implements ReactiveHealthIndicator {

	private static final Duration CACHE_TTL = Duration.ofSeconds(10);

	private final WormObjectStore worm;
	private final WormProperties properties;

	private volatile Health cached;
	private volatile long cachedUntilNanos;

	public WormHealthIndicator(WormObjectStore worm, WormProperties properties) {
		this.worm = worm;
		this.properties = properties;
	}

	@Override
	public Mono<Health> health() {
		if (!properties.isReadinessGate()) {
			return Mono.just(Health.up().withDetail("worm", "gate-disabled").build());
		}
		Health snapshot = cached;
		if (snapshot != null && System.nanoTime() < cachedUntilNanos) {
			return Mono.just(snapshot);
		}
		return worm.probe().thenReturn(Health.up().build())
				.onErrorResume(error -> Mono.just(Health.outOfService().withDetail("worm", "unreachable").build()))
				.doOnNext(health -> {
					this.cached = health;
					this.cachedUntilNanos = System.nanoTime() + CACHE_TTL.toNanos();
				});
	}
}
