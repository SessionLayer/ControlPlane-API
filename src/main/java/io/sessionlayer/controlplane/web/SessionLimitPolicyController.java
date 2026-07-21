package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.SessionLimitPoliciesApi;
import io.sessionlayer.controlplane.api.model.CreateSessionLimitPolicyRequest;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.SessionLimitPolicyPage;
import io.sessionlayer.controlplane.api.model.SessionLimitPolicyResource;
import io.sessionlayer.controlplane.api.model.UpdateSessionLimitPolicyRequest;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.configapi.SessionLimitPolicyConfigService;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicy;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

/**
 * CRUD for session-limit policies ({@code config.session_limit_policy},
 * FR-SESS-3 / FR-API-2). Reads need {@code rbac:read}; writes need
 * {@code settings:write}. Every mutation is audited + pre-commit-validated by
 * {@link SessionLimitPolicyConfigService}; creates are idempotency-key guarded.
 */
@RestController
public class SessionLimitPolicyController implements SessionLimitPoliciesApi {

	private final SessionLimitPolicyConfigService policies;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;
	private final ObjectMapper mapper;

	public SessionLimitPolicyController(SessionLimitPolicyConfigService policies, PlatformAccess access,
			IdempotencyService idempotency, ObjectMapper mapper) {
		this.policies = policies;
		this.access = access;
		this.idempotency = idempotency;
		this.mapper = mapper;
	}

	@Override
	public Mono<ResponseEntity<SessionLimitPolicyPage>> listSessionLimitPolicies(String cursor, Integer limit,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ,
				subject -> policies.list(cursor, limit)
						.map(page -> ResponseEntity
								.ok(new SessionLimitPolicyPage(page.items().stream().map(this::toResource).toList())
										.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<SessionLimitPolicyResource>> createSessionLimitPolicy(
			Mono<CreateSessionLimitPolicyRequest> createSessionLimitPolicyRequest, String idempotencyKey,
			ServerWebExchange exchange) {
		return createSessionLimitPolicyRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> {
					Mono<ResponseEntity<SessionLimitPolicyResource>> action = policies.create(subject.identity(),
							req.getName(), ApiConversions.toJson(mapper, req.getIdentitySelector()),
							req.getMaxConcurrentSessions(), req.getMaxSessionSeconds(), req.getIdleTimeoutSeconds())
							.map(policy -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(policy)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, SessionLimitPolicyResource.class, action);
				}));
	}

	@Override
	public Mono<ResponseEntity<SessionLimitPolicyResource>> getSessionLimitPolicy(UUID sessionLimitPolicyId,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ,
				subject -> policies.get(sessionLimitPolicyId).map(policy -> ResponseEntity.ok(toResource(policy))));
	}

	@Override
	public Mono<ResponseEntity<SessionLimitPolicyResource>> updateSessionLimitPolicy(UUID sessionLimitPolicyId,
			Mono<UpdateSessionLimitPolicyRequest> updateSessionLimitPolicyRequest, ServerWebExchange exchange) {
		return updateSessionLimitPolicyRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.SETTINGS_WRITE,
						subject -> policies.update(sessionLimitPolicyId, subject.identity(), req.getVersion(),
								ApiConversions.toJson(mapper, req.getIdentitySelector()),
								req.getMaxConcurrentSessions(), req.getMaxSessionSeconds(), req.getIdleTimeoutSeconds())
								.map(policy -> ResponseEntity.ok(toResource(policy)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteSessionLimitPolicy(UUID sessionLimitPolicyId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> policies
				.delete(sessionLimitPolicyId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	private SessionLimitPolicyResource toResource(SessionLimitPolicy policy) {
		SessionLimitPolicyResource resource = new SessionLimitPolicyResource(policy.id(), policy.name(),
				ApiConversions.toMap(mapper, policy.identitySelector()), Origin.fromValue(policy.origin()),
				policy.version());
		resource.setMaxConcurrentSessions(policy.maxConcurrentSessions());
		resource.setMaxSessionSeconds(policy.maxSessionSeconds());
		resource.setIdleTimeoutSeconds(policy.idleTimeoutSeconds());
		resource.setCreatedAt(ApiConversions.toOffset(policy.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(policy.updatedAt()));
		return resource;
	}
}
