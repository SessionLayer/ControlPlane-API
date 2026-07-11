package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link OidcLogin} ({@code runtime.oidc_login}). */
public interface OidcLoginRepository extends ReactiveCrudRepository<OidcLogin, UUID> {

	Mono<OidcLogin> findByStateHash(String stateHash);
}
