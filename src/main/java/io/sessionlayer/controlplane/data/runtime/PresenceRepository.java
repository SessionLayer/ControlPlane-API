package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

/**
 * Reactive repository for {@link Presence} ({@code runtime.presence}), keyed by
 * {@code nodeId}. {@code findByOwningGateway} backs the "which nodes does
 * gateway G own" routing/failover lookup (Design §10.2).
 */
public interface PresenceRepository extends ReactiveCrudRepository<Presence, UUID> {

	Flux<Presence> findByOwningGateway(String owningGateway);
}
