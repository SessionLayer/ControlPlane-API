package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

/**
 * Reactive repository for {@link AccessLock} ({@code runtime.access_lock},
 * API-only).
 */
public interface AccessLockRepository extends ReactiveCrudRepository<AccessLock, UUID> {

	Flux<AccessLock> findByMode(String mode);
}
