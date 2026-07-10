package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link DpRule} ({@code config.dp_rule}). */
public interface DpRuleRepository extends ReactiveCrudRepository<DpRule, UUID> {

	Mono<DpRule> findByName(String name);

	Flux<DpRule> findByEffect(String effect);
}
