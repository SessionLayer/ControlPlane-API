package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.AuditEventsApi;
import io.sessionlayer.controlplane.api.model.AccessModel;
import io.sessionlayer.controlplane.api.model.AuditEventPage;
import io.sessionlayer.controlplane.api.model.AuditEventResource;
import io.sessionlayer.controlplane.api.model.Capability;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Correlated audit-stream admin surface ({@code runtime.audit_event}, Design
 * §12.2). Placeholder implementation — Session 18 (Part B) replaces the bodies
 * with the {@code audit:read}-gated, RBAC-scope-filtered search/get.
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
			OffsetDateTime from, OffsetDateTime to, Capability capability, AccessModel accessModel,
			List<String> nodeLabel, UUID correlationId, ServerWebExchange exchange) {
		return frozen();
	}

	@Override
	public Mono<ResponseEntity<AuditEventResource>> getAuditEvent(UUID auditEventId, ServerWebExchange exchange) {
		return frozen();
	}

	private <T> Mono<ResponseEntity<T>> frozen() {
		return access.withPermission(PlatformPermissions.AUDIT_READ,
				subject -> Mono.error(ApiProblemException.notImplemented("audit-events")));
	}
}
