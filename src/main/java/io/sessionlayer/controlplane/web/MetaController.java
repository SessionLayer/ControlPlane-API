package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.MetaApi;
import io.sessionlayer.controlplane.api.model.HealthStatus;
import io.sessionlayer.controlplane.api.model.ProtocolRanges;
import io.sessionlayer.controlplane.api.model.ProtocolVersionRange;
import io.sessionlayer.controlplane.api.model.VersionInfo;
import io.sessionlayer.controlplane.config.ComponentDescriptor;
import io.sessionlayer.controlplane.protocol.ProtocolVersions;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Implements the contract-first meta probes generated from
 * {@code contracts/openapi/openapi.yaml} ({@link MetaApi}). Both endpoints are
 * public, unauthenticated, and non-leaking (FR-API-1, Design §7.1). Session One
 * scope is only these operational probes; the full resource surface arrives in
 * later sessions.
 */
@RestController
public class MetaController implements MetaApi {

	private final ComponentDescriptor descriptor;

	public MetaController(ComponentDescriptor descriptor) {
		this.descriptor = descriptor;
	}

	@Override
	public Mono<ResponseEntity<HealthStatus>> getHealth(final ServerWebExchange exchange) {
		// Liveness: if this handler runs, the process is serving requests. The detailed
		// readiness
		// check (DB reachability via R2DBC) lives behind /actuator/health, which also
		// must not leak
		// identity/node/policy detail (management.endpoint.health.show-details=never).
		return Mono.just(ResponseEntity.ok(new HealthStatus(HealthStatus.StatusEnum.PASS)));
	}

	@Override
	public Mono<ResponseEntity<VersionInfo>> getVersion(final ServerWebExchange exchange) {
		// Session One baseline: both protocol planes are 1.0 (VERSIONING.md §6). The
		// CP<->Gateway
		// range comes from ProtocolVersions (shared with the gRPC Handshake server);
		// the
		// Agent<->Gateway wire baseline is the same 1.0 this session.
		String current = ProtocolVersions.display(ProtocolVersions.CURRENT);
		ProtocolVersionRange range = new ProtocolVersionRange(current, current);
		ProtocolRanges protocols = new ProtocolRanges(range, range);
		VersionInfo info = new VersionInfo(descriptor.name(), descriptor.version(), protocols);
		return Mono.just(ResponseEntity.ok(info));
	}
}
