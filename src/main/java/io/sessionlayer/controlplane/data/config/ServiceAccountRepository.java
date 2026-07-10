package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link ServiceAccount}
 * ({@code config.service_account}).
 */
public interface ServiceAccountRepository extends ReactiveCrudRepository<ServiceAccount, UUID> {

	Mono<ServiceAccount> findByName(String name);
}
