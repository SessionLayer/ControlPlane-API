package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link CaConfig} ({@code config.ca_config}). */
public interface CaConfigRepository extends ReactiveCrudRepository<CaConfig, UUID> {

	Mono<CaConfig> findByCaKind(String caKind);
}
