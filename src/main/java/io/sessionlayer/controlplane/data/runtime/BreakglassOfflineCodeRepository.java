package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

/**
 * Reactive repository for {@link BreakglassOfflineCode}
 * ({@code runtime.breakglass_offline_code}). Consumption is an atomic mark-used
 * UPDATE via {@code DatabaseClient} (mirrors {@code OtpService}), not through
 * this repository, so a replay matches no row.
 */
public interface BreakglassOfflineCodeRepository extends ReactiveCrudRepository<BreakglassOfflineCode, UUID> {

	Flux<BreakglassOfflineCode> findByIdentity(String identity);
}
