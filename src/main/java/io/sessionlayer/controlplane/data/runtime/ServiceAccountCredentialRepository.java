package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link ServiceAccountCredential}. */
public interface ServiceAccountCredentialRepository extends ReactiveCrudRepository<ServiceAccountCredential, UUID> {

	Flux<ServiceAccountCredential> findByServiceAccountId(UUID serviceAccountId);

	Flux<ServiceAccountCredential> findByServiceAccountIdAndStatus(UUID serviceAccountId, String status);

	Mono<ServiceAccountCredential> findBySecretHashAndStatus(String secretHash, String status);

	Mono<ServiceAccountCredential> findByFingerprintAndStatus(String fingerprint, String status);
}
