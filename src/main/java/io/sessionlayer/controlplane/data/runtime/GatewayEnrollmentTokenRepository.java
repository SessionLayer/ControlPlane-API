package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link GatewayEnrollmentToken}
 * ({@code runtime.gateway_enrollment_token}). Lookup is by the token hash (the
 * raw token is never stored); single-use consumption is an optimistic
 * {@code @Version}-guarded save on {@code consumedAt}.
 */
public interface GatewayEnrollmentTokenRepository extends ReactiveCrudRepository<GatewayEnrollmentToken, UUID> {

	Mono<GatewayEnrollmentToken> findByTokenHash(String tokenHash);
}
