package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link BreakglassToken}
 * ({@code runtime.breakglass_token}).
 */
public interface BreakglassTokenRepository extends ReactiveCrudRepository<BreakglassToken, UUID> {

	Mono<BreakglassToken> findByTokenHash(String tokenHash);
}
