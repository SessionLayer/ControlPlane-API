package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link JoinToken} ({@code runtime.join_token}). */
public interface JoinTokenRepository extends ReactiveCrudRepository<JoinToken, UUID> {

	Mono<JoinToken> findByTokenHash(String tokenHash);
}
