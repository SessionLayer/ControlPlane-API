package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for the {@link PolicyEpoch} singleton. */
public interface PolicyEpochRepository extends ReactiveCrudRepository<PolicyEpoch, UUID> {

	@Query("SELECT * FROM config.policy_epoch WHERE singleton = true")
	Mono<PolicyEpoch> findSingleton();
}
