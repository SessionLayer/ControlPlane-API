package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

/** Reactive repository for {@link JitRequest} ({@code runtime.jit_request}). */
public interface JitRequestRepository extends ReactiveCrudRepository<JitRequest, UUID> {

	Flux<JitRequest> findByState(String state);

	Flux<JitRequest> findByRequester(String requester);
}
