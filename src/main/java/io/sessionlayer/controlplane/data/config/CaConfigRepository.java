package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link CaConfig} ({@code config.ca_config}). */
public interface CaConfigRepository extends ReactiveCrudRepository<CaConfig, UUID> {

	/**
	 * All rows for a CA kind (a kind may have several during a rotation overlap).
	 */
	Flux<CaConfig> findByCaKind(String caKind);

	/**
	 * The single active config for a kind (partial unique index guarantees ≤ 1).
	 */
	Mono<CaConfig> findByCaKindAndRotationState(String caKind, String rotationState);

	Mono<CaConfig> findByName(String name);
}
