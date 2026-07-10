package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link CapabilityDef}
 * ({@code config.capability_def}).
 */
public interface CapabilityDefRepository extends ReactiveCrudRepository<CapabilityDef, UUID> {

	Mono<CapabilityDef> findByName(String name);
}
