package io.sessionlayer.controlplane.data.config;

import java.util.UUID;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for the {@link OperatorSettings} singleton. */
public interface OperatorSettingsRepository extends ReactiveCrudRepository<OperatorSettings, UUID> {

	/** The single settings row (there is at most one, DB-enforced). */
	@Query("SELECT * FROM config.operator_settings WHERE singleton = true")
	Mono<OperatorSettings> findSingleton();
}
