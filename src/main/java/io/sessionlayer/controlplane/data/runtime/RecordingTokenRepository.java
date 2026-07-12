package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link RecordingToken}
 * ({@code runtime.recording_token}). Lookup is by the token hash; the
 * single-use marking is an optimistic {@code @Version}-guarded save on
 * {@code used} (replay is rejected).
 */
public interface RecordingTokenRepository extends ReactiveCrudRepository<RecordingToken, UUID> {

	Mono<RecordingToken> findByTokenHash(String tokenHash);
}
