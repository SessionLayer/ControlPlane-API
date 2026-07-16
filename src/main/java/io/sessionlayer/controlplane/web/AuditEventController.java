package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.AuditEventsApi;
import io.sessionlayer.controlplane.api.model.AuditEventPage;
import io.sessionlayer.controlplane.api.model.AuditEventResource;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Correlated audit-stream admin surface ({@code runtime.audit_event}, Design
 * §12.2). FROZEN CONTRACT: the routes exist and are RBAC-gated on
 * {@code audit:read} so an unauthorized caller still gets {@code 403}, but
 * every operation returns {@code 501} until Session 18 implements the
 * search/get query.
 */
@RestController
public class AuditEventController implements AuditEventsApi {

	private final PlatformAccess access;

	public AuditEventController(PlatformAccess access) {
		this.access = access;
	}

	@Override
	public Mono<ResponseEntity<AuditEventPage>> searchAuditEvents(String cursor, Integer limit, String actor,
			String subject, String action, String outcome, UUID sessionId, UUID nodeId, String sourceIp,
			OffsetDateTime from, OffsetDateTime to, ServerWebExchange exchange) {
		return frozen();
	}

	@Override
	public Mono<ResponseEntity<AuditEventResource>> getAuditEvent(UUID auditEventId, ServerWebExchange exchange) {
		return frozen();
	}

	// Gate on audit:read first (an unauthorized caller still gets 403), then fail
	// with a 501 problem — the contract is frozen, the behaviour lands in S18.
	private <T> Mono<ResponseEntity<T>> frozen() {
		return access.withPermission(PlatformPermissions.AUDIT_READ,
				subject -> Mono.error(ApiProblemException.notImplemented("audit-events")));
	}
}
