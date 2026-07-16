package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Mono;

/** Reactive repository for {@link IdempotencyRecord} ({@code runtime.idempotency_key}). */
public interface IdempotencyRecordRepository extends ReactiveCrudRepository<IdempotencyRecord, UUID> {

	Mono<IdempotencyRecord> findByPrincipalAndMethodAndPathAndIdempotencyKey(String principal, String method,
			String path, String idempotencyKey);
}
