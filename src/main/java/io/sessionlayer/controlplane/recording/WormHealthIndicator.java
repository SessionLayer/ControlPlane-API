package io.sessionlayer.controlplane.recording;

import java.time.Duration;
import org.springframework.boot.health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Observability for the WORM recording store: reports the store's true
 * reachability (HEAD bucket, cached for a short TTL so the endpoint never
 * hammers it) so operators can alert on a degraded store. Contributes to
 * {@code /actuator/health}; detail is not exposed ({@code show-details=never}).
 *
 * <p>
 * It does <b>not</b> gate readiness by default — WORM is a shared store, so an
 * outage is cluster-wide, and readiness-gating it would deregister every CP
 * (auth/CA/RBAC/audit-query too) for a problem that only affects new recorded
 * sessions (which already fail closed loudly + emit an out-of-band failure
 * audit), and it would defeat incident response (auditors can't query
 * mid-incident). An operator running a per-CP / node-local store can opt in by
 * adding {@code worm} to
 * {@code management.endpoint.health.group.readiness.include} (the standard Boot
 * mechanism). Disable the contributor entirely with
 * {@code management.health.worm.enabled=false} (e.g. a store-less test
 * context).
 */
@Component("worm")
@ConditionalOnEnabledHealthIndicator("worm")
public class WormHealthIndicator implements ReactiveHealthIndicator {

	private static final Duration CACHE_TTL = Duration.ofSeconds(10);

	private final WormObjectStore worm;

	private volatile Health cached;
	private volatile long cachedUntilNanos;

	public WormHealthIndicator(WormObjectStore worm) {
		this.worm = worm;
	}

	@Override
	public Mono<Health> health() {
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
