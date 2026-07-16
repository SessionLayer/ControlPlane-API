package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.RulesApi;
import io.sessionlayer.controlplane.api.model.CreateRuleRequest;
import io.sessionlayer.controlplane.api.model.Effect;
import io.sessionlayer.controlplane.api.model.Origin;
import io.sessionlayer.controlplane.api.model.RulePage;
import io.sessionlayer.controlplane.api.model.RuleResource;
import io.sessionlayer.controlplane.api.model.UpdateRuleRequest;
import io.sessionlayer.controlplane.configapi.IdempotencyService;
import io.sessionlayer.controlplane.configapi.RuleConfigService;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

/**
 * CRUD for data-plane rules (`config.dp_rule`, FR-API-2). Reads need
 * {@code rbac:read}; writes need {@code rbac:write}. Every mutation is audited +
 * pre-commit-validated by {@link RuleConfigService}; creates are idempotency-key
 * guarded. The exemplar the other Session 17 config controllers follow.
 */
@RestController
public class RuleController implements RulesApi {

	private final RuleConfigService rules;
	private final PlatformAccess access;
	private final IdempotencyService idempotency;
	private final ObjectMapper mapper;

	public RuleController(RuleConfigService rules, PlatformAccess access, IdempotencyService idempotency,
			ObjectMapper mapper) {
		this.rules = rules;
		this.access = access;
		this.idempotency = idempotency;
		this.mapper = mapper;
	}

	@Override
	public Mono<ResponseEntity<RulePage>> listRules(String cursor, Integer limit, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ,
				subject -> rules.list(cursor, limit).map(page -> ResponseEntity.ok(new RulePage(
						page.items().stream().map(this::toResource).toList()).nextCursor(page.nextCursor()))));
	}

	@Override
	public Mono<ResponseEntity<RuleResource>> createRule(Mono<CreateRuleRequest> createRuleRequest,
			String idempotencyKey, ServerWebExchange exchange) {
		return createRuleRequest.flatMap(req -> access.withPermission(PlatformPermissions.RBAC_WRITE, subject -> {
			Mono<ResponseEntity<RuleResource>> action = rules
					.create(subject.identity(), req.getName(),
							ApiConversions.toJson(mapper, req.getIdentitySelector()),
							ApiConversions.toJson(mapper, req.getNodeLabelSelector()),
							ApiConversions.toJsonOrNull(mapper, req.getSourceIpCondition()), req.getPrincipals(),
							ttl(req.getTtlSeconds()), ApiConversions.capabilityValues(req.getCapabilities()),
							req.getEffect().getValue())
					.map(rule -> ResponseEntity.status(HttpStatus.CREATED).body(toResource(rule)));
			return idempotency.execute(idempotencyKey, subject.identity(), method(exchange), path(exchange), req,
					RuleResource.class, action);
		}));
	}

	@Override
	public Mono<ResponseEntity<RuleResource>> getRule(UUID ruleId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_READ,
				subject -> rules.get(ruleId).map(rule -> ResponseEntity.ok(toResource(rule))));
	}

	@Override
	public Mono<ResponseEntity<RuleResource>> updateRule(UUID ruleId, Mono<UpdateRuleRequest> updateRuleRequest,
			ServerWebExchange exchange) {
		return updateRuleRequest
				.flatMap(req -> access.withPermission(PlatformPermissions.RBAC_WRITE, subject -> rules
						.update(ruleId, subject.identity(), req.getVersion(),
								ApiConversions.toJson(mapper, req.getIdentitySelector()),
								ApiConversions.toJson(mapper, req.getNodeLabelSelector()),
								ApiConversions.toJsonOrNull(mapper, req.getSourceIpCondition()), req.getPrincipals(),
								ttl(req.getTtlSeconds()), ApiConversions.capabilityValues(req.getCapabilities()),
								req.getEffect().getValue())
						.map(rule -> ResponseEntity.ok(toResource(rule)))));
	}

	@Override
	public Mono<ResponseEntity<Void>> deleteRule(UUID ruleId, ServerWebExchange exchange) {
		return access.withPermission(PlatformPermissions.RBAC_WRITE, subject -> rules.delete(ruleId, subject.identity())
				.thenReturn(ResponseEntity.noContent().build()));
	}

	private RuleResource toResource(DpRule rule) {
		RuleResource resource = new RuleResource(rule.id(), rule.name(),
				ApiConversions.toMap(mapper, rule.identitySelector()),
				ApiConversions.toMap(mapper, rule.nodeLabelSelector()), rule.principals(), rule.ttlSeconds(),
				ApiConversions.toCapabilities(rule.capabilities()), Effect.fromValue(rule.effect()),
				Origin.fromValue(rule.origin()), rule.version());
		resource.setSourceIpCondition(
				rule.sourceIpCondition() == null ? null : ApiConversions.toMap(mapper, rule.sourceIpCondition()));
		resource.setCreatedAt(ApiConversions.toOffset(rule.createdAt()));
		resource.setUpdatedAt(ApiConversions.toOffset(rule.updatedAt()));
		return resource;
	}

	// A required ttl absent at the bean-validation layer would already be a 400; -1
	// funnels any residual null to the service's pre-commit 422 rather than an NPE.
	private static int ttl(Integer ttlSeconds) {
		return ttlSeconds == null ? -1 : ttlSeconds;
	}

	static String method(ServerWebExchange exchange) {
		return exchange.getRequest().getMethod().name();
	}

	static String path(ServerWebExchange exchange) {
		return exchange.getRequest().getPath().value();
	}
}
