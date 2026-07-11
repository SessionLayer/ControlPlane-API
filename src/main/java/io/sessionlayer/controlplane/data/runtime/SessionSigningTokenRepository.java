package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link SessionSigningToken}
 * ({@code runtime.session_signing_token}). Lookup is by the token hash; the
 * single-use marking is an optimistic {@code @Version}-guarded save on
 * {@code used} (replay is rejected).
 */
public interface SessionSigningTokenRepository extends ReactiveCrudRepository<SessionSigningToken, UUID> {

	Mono<SessionSigningToken> findByTokenHash(String tokenHash);
}
