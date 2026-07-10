package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

/** Reactive repository for {@link ServiceAccountCredential}. */
public interface ServiceAccountCredentialRepository extends ReactiveCrudRepository<ServiceAccountCredential, UUID> {

	Flux<ServiceAccountCredential> findByServiceAccountId(UUID serviceAccountId);
}
