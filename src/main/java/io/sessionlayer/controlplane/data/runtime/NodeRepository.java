package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link Node} ({@code runtime.node}). */
public interface NodeRepository extends ReactiveCrudRepository<Node, UUID> {

	Mono<Node> findByName(String name);

	Flux<Node> findByStatus(String status);
}
