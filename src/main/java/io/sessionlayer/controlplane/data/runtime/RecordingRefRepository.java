package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/**
 * Reactive repository for {@link RecordingRef} ({@code runtime.recording_ref}).
 */
public interface RecordingRefRepository extends ReactiveCrudRepository<RecordingRef, UUID> {

	Mono<RecordingRef> findBySessionId(UUID sessionId);
}
