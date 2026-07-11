package io.sessionlayer.controlplane.mtls;

import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Readiness for the self-managed mTLS gRPC plane (L4): a live JVM whose gRPC
 * listener is down must not read healthy. Contributes to
 * {@code /actuator/health} (its detail is not exposed —
 * {@code show-details=never}). When the plane is disabled it reports UP (there
 * is nothing to be unhealthy about); when enabled it is UP only while the
 * listener is actually running, and OUT_OF_SERVICE otherwise — including during
 * graceful shutdown, so the LB stops routing before the drain (paired with the
 * {@code running}-first flip in {@link GrpcMtlsServer#stop()}).
 */
@Component
public class GrpcMtlsServerHealthIndicator implements HealthIndicator {

	private final GrpcMtlsServer server;
	private final MtlsProperties properties;

	public GrpcMtlsServerHealthIndicator(GrpcMtlsServer server, MtlsProperties properties) {
		this.server = server;
		this.properties = properties;
	}

	@Override
	public Health health() {
		if (!properties.getServer().isEnabled()) {
			return Health.up().withDetail("grpcMtls", "disabled").build();
		}
		return server.isRunning()
				? Health.up().withDetail("grpcMtls", "listening").build()
				: Health.outOfService().withDetail("grpcMtls", "not listening").build();
	}
}
