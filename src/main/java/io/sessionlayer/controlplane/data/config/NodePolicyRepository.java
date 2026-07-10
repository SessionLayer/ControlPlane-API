package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link NodePolicy} ({@code config.node_policy}). */
public interface NodePolicyRepository extends ReactiveCrudRepository<NodePolicy, UUID> {

	Mono<NodePolicy> findByName(String name);
}
