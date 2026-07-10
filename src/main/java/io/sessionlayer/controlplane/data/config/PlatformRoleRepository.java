package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link PlatformRole} ({@code config.platform_role}).
 */
public interface PlatformRoleRepository extends ReactiveCrudRepository<PlatformRole, UUID> {

	Mono<PlatformRole> findByName(String name);
}
