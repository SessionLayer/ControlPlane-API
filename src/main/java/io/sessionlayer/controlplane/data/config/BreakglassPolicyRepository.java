package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link BreakglassPolicy}
 * ({@code config.breakglass_policy}).
 */
public interface BreakglassPolicyRepository extends ReactiveCrudRepository<BreakglassPolicy, UUID> {

	Mono<BreakglassPolicy> findByName(String name);
}
