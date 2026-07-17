package io.sessionlayer.controlplane.ca;

import java.time.Duration;
import org.springframework.boot.health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.ReactiveHealthIndicator;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * NFR-3 session-CA signing availability, as an {@code /actuator/health}
 * contributor (Design §14 — an SLO peer of the datastore). Reports whether an
 * active session signer can be obtained (UP) or not (OUT_OF_SERVICE, the
 * fail-closed state {@code CaSignerService} already enforces). Cached for a
 * short TTL so the probe never hammers the datastore.
 *
 * <p>
 * Like {@code WormHealthIndicator} it does <b>not</b> gate readiness by default:
 * a session-CA rotation gap is serious, but deregistering every CP (auth /
 * RBAC / audit-query too) on it would defeat incident response, and the
 * availability <i>metric</i> ({@code sessionlayer.ca.signer}) is the SLI that
 * alerts. An operator can opt in by adding {@code caSigner} to
 * {@code management.endpoint.health.group.readiness.include}, or disable this
 * contributor with {@code management.health.caSigner.enabled=false}.
 */
@Component("caSigner")
@ConditionalOnEnabledHealthIndicator("caSigner")
public class CaSignerHealthIndicator implements ReactiveHealthIndicator {

	private static final Duration CACHE_TTL = Duration.ofSeconds(10);

	private final CaSignerService signers;

	private volatile Health cached;
	private volatile long cachedUntilNanos;

	public CaSignerHealthIndicator(CaSignerService signers) {
		this.signers = signers;
	}

	@Override
	public Mono<Health> health() {
		Health snapshot = cached;
		if (snapshot != null && System.nanoTime() < cachedUntilNanos) {
			return Mono.just(snapshot);
		}
		return signers.activeSigner("session").thenReturn(Health.up().build())
				.onErrorResume(error -> Mono.just(Health.outOfService().withDetail("caSigner", "no active signer").build()))
				.doOnNext(health -> {
					this.cached = health;
					this.cachedUntilNanos = System.nanoTime() + CACHE_TTL.toNanos();
				});
	}
}
