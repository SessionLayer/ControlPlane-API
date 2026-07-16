package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.JitPoliciesApi;
import io.sessionlayer.controlplane.api.model.CreateJitPolicyRequest;
import io.sessionlayer.controlplane.api.model.JitApprovalLevel;
import io.sessionlayer.controlplane.api.model.JitPolicyPage;
import io.sessionlayer.controlplane.api.model.JitPolicyResource;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.UpdateJitPolicyRequest;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.configapi.JitPolicyConfigService;
import io.sessionlayer.controlplane.data.config.JitPolicy;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * CRUD for JIT-access policies (`config.jit_policy`, FR-ACC-3). All operations
 * need {@code settings:write}. Every mutation is audited + pre-commit-validated
 * by {@link JitPolicyConfigService}; creates are idempotency-key guarded.
 */
@RestController
public class JitPolicyController implements JitPoliciesApi {

	private final JitPolicyConfigService policies;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;
	private final ObjectMapper mapper;

	public JitPolicyController(JitPolicyConfigService policies, PlatformAccess access, IdempotencyService idempotency,
			ObjectMapper mapper) {
		this.policies = policies;
		this.access = access;
		this.idempotency = idempotency;
		this.mapper = mapper;
	}

	@Override
	public Mono<ResponseEntity<JitPolicyPage>> listJitPolicies(String cursor, Integer limit,
			ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> policies.list(cursor, limit)
				.map(page -> ResponseEntity.ok(new JitPolicyPage(page.items().stream().map(this::toResource).toList())
						.nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<JitPolicyResource>> createJitPolicy(Mono<CreateJitPolicyRequest> createJitPolicyRequest,
			String idempotencyKey, ServerWebExchange exchange) {
		return createJitPolicyRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> {
					Mono<ResponseEntity<JitPolicyResource>> action = policies
							.create(subject.identity(), req.getName(),
									ApiConversions.toJson(mapper, req.getTargetSelector()),
									ApiConversions.capabilityValues(req.getCapabilities()), ttl(req.getMaxTtlSeconds()),
									chainJson(req.getApprovalChain()))
							.map(policy -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(policy)));
					return idempotency.execute(idempotencyKey, subject.identity(), ApiConversions.method(exchange),
							ApiConversions.path(exchange), req, JitPolicyResource.class, action);
				}));
	}

	@Override
	public Mono<ResponseEntity<JitPolicyResource>> getJitPolicy(UUID jitPolicyId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE,
				subject -> policies.get(jitPolicyId).map(policy -> ResponseEntity.ok(toResource(policy))));
	}

	@Override
	public Mono<ResponseEntity<JitPolicyResource>> updateJitPolicy(UUID jitPolicyId,
			Mono<UpdateJitPolicyRequest> updateJitPolicyRequest, ServerWebExchange exchange) {
		return updateJitPolicyRequest.flatMap(req -> access.withPermission(PlatformPermissions.SETTINGS_WRITE,
				subject -> policies
						.update(jitPolicyId, subject.identity(), req.getVersion(),
								ApiConversions.toJson(mapper, req.getTargetSelector()),
								ApiConversions.capabilityValues(req.getCapabilities()), ttl(req.getMaxTtlSeconds()),
								chainJson(req.getApprovalChain()))
						.map(policy -> ResponseEntity.ok(toResource(policy)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteJitPolicy(UUID jitPolicyId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.SETTINGS_WRITE, subject -> policies
				.delete(jitPolicyId, subject.identity()).thenReturn(ResponseEntity.noContent().build()));
	}

	private JitPolicyResource toResource(JitPolicy policy) {
		JitPolicyResource resource = new JitPolicyResource(policy.id(), policy.name(),
				ApiConversions.toMap(mapper, policy.targetSelector()),
				ApiConversions.toCapabilities(policy.capabilities()), policy.maxTtlSeconds(),
				approvalLevels(policy.approvalChain()), Origin.fromValue(policy.origin()), policy.version());
		resource.setCreatedAt(ApiConversions.toOffset(policy.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(policy.updatedAt()));
		return resource;
	}

	private JsonNode chainJson(List<JitApprovalLevel> chain) {
		return chain == null ? mapper.createArrayNode() : mapper.valueToTree(chain);
	}

	private static List<JitApprovalLevel> approvalLevels(JsonNode chain) {
		List<JitApprovalLevel> levels = new ArrayList<>();
		if (chain != null && chain.isArray()) {
			for (JsonNode level : chain) {
				JitApprovalLevel out = new JitApprovalLevel().value(text(level, "value"));
				String kind = text(level, "kind");
				if ("email".equals(kind) || "oidc_group".equals(kind)) {
					out.setKind(JitApprovalLevel.KindEnum.fromValue(kind));
				}
				levels.add(out);
			}
		}
		return levels;
	}

	private static String text(JsonNode node, String field) {
		JsonNode value = node == null ? null : node.get(field);
		return value != null && value.isString() ? value.stringValue() : null;
	}

	// A required maxTtlSeconds absent at the bean-validation layer would already be
	// a 400; -1 funnels any residual null to the service's pre-commit 422.
	private static int ttl(Integer maxTtlSeconds) {
		return maxTtlSeconds == null ? -1 : maxTtlSeconds;
	}
}
