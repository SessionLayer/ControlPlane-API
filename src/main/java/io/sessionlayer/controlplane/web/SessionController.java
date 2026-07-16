package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.SessionsApi;
import io.sessionlayer.controlplane.api.model.AccessModel;
import io.sessionlayer.controlplane.api.model.SessionPage;
import io.sessionlayer.controlplane.api.model.SessionResource;
import io.sessionlayer.controlplane.api.model.TerminateSessionRequest;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.configapi.SessionManagementService;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Admin read + teardown for RUNTIME SSH sessions ({@code runtime.ssh_session},
 * Design §12A). List/get are RBAC-gated on {@code audit:read}; terminate needs
 * {@code lock:write} because it pushes a top-tier {@code Lock} deny (S10 §8.3/
 * §8.4) and is idempotency-key guarded + audited by
 * {@link SessionManagementService}. Read-only over session state — the Gateway
 * owns the session lifecycle.
 */
@RestController
public class SessionController implements SessionsApi {

	private final SessionManagementService sessions;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;

	public SessionController(SessionManagementService sessions, PlatformAccess access, IdempotencyService idempotency) {
		this.sessions = sessions;
		this.access = access;
		this.idempotency = idempotency;
	}

	@Override
	public Mono<ResponseEntity<SessionPage>> listSessions(String cursor, Integer limit, String identity, UUID nodeId,
			String accessModel, Boolean activeOnly, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.AUDIT_READ,
				subject -> sessions.list(cursor, limit, identity, nodeId, accessModel, activeOnly).map(
						page -> ResponseEntity.ok(new SessionPage(page.items().stream().map(this::toResource).toList())
								.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<SessionResource>> getSession(UUID sessionId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.AUDIT_READ,
				subject -> sessions.get(sessionId).map(session -> ResponseEntity.ok(toResource(session))));
	}

	@Override
	public Mono<ResponseEntity<SessionResource>> terminateSession(UUID sessionId, String idempotencyKey,
			Mono<TerminateSessionRequest> terminateSessionRequest, ServerWebExchange exchange) {
		// The body (a reason) is optional; supply an empty default so a bodiless
		// terminate still runs and fingerprints deterministically for idempotency.
		return terminateSessionRequest.defaultIfEmpty(new TerminateSessionRequest())
				.flatMap(req -> access.withPermission(PlatformPermissions.LOCK_WRITE, subject -> {
					Mono<ResponseEntity<SessionResource>> action = sessions
							.terminate(sessionId, subject.identity(), req.getReason())
							.map(session -> ResponseEntity.status(HttpStatus.ACCEPTED).body(toResource(session)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, SessionResource.class, action);
				}));
	}

	private SessionResource toResource(SshSession session) {
		SessionResource resource = new SessionResource(session.id(), session.identity(), session.principal(),
				AccessModel.fromValue(session.accessModel()), ApiConversions.toCapabilities(session.capabilities()),
				ApiConversions.toOffset(session.startedAt()));
		resource.setNodeId(session.nodeId());
		resource.setNodeName(session.nodeName());
		resource.setGatewayId(session.gatewayId());
		resource.setGatewayName(session.gatewayName());
		resource.setMatchedRuleId(session.matchedRuleId());
		resource.setMatchedRuleName(session.matchedRuleName());
		resource.setJitRequestId(session.jitRequestId());
		resource.setBreakglassActivationId(session.breakglassActivationId());
		resource.setPolicyEpoch(session.policyEpoch());
		resource.setGrantExpiry(ApiConversions.toOffset(session.grantExpiry()));
		resource.setEndedAt(ApiConversions.toOffset(session.endedAt()));
		resource.setEndReason(session.endReason());
		return resource;
	}
}
