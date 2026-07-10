package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link GatewayIdentity}
 * ({@code runtime.gateway_identity}).
 */
public interface GatewayIdentityRepository extends ReactiveCrudRepository<GatewayIdentity, UUID> {

	Mono<GatewayIdentity> findByName(String name);
}
