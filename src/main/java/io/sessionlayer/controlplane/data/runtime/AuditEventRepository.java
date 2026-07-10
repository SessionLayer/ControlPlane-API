package io.sessionlayer.controlplane.data.runtime;

import java.util.UUID;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;

/**
 * Reactive repository for {@link AuditEvent} ({@code runtime.audit_event}).
 * Insert and read only — the table is append-only (a DB trigger rejects
 * UPDATE/DELETE), so callers MUST NOT invoke {@code save()} on an
 * already-persisted row nor any delete method. The finders back the FR-AUD-8/9
 * search + correlation paths.
 */
public interface AuditEventRepository extends ReactiveCrudRepository<AuditEvent, UUID> {

	Flux<AuditEvent> findByCorrelationId(UUID correlationId);

	Flux<AuditEvent> findByActor(String actor);

	Flux<AuditEvent> findBySessionId(UUID sessionId);
}
