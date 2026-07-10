package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

/**
 * Reactive repository for {@link RoleBinding} ({@code config.role_binding}).
 */
public interface RoleBindingRepository extends ReactiveCrudRepository<RoleBinding, UUID> {

	Flux<RoleBinding> findByRoleId(UUID roleId);
}
