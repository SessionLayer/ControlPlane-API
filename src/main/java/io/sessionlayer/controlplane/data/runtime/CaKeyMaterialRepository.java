package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link CaKeyMaterial} (KEK-wrapped local CA keys).
 */
public interface CaKeyMaterialRepository extends ReactiveCrudRepository<CaKeyMaterial, UUID> {

	Mono<CaKeyMaterial> findByCaConfigId(UUID caConfigId);
}
