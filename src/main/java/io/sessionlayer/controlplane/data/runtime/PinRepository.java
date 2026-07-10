package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link Pin} ({@code runtime.pin}). */
public interface PinRepository extends ReactiveCrudRepository<Pin, UUID> {

	Mono<Pin> findByFingerprintAndIdentity(String fingerprint, String identity);

	Flux<Pin> findByIdentity(String identity);
}
