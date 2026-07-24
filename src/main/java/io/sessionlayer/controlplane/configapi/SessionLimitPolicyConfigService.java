package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicy;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicyRepository;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.CursorPages;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

/**
 * Config CRUD for session-limit policies ({@code config.session_limit_policy},
 * FR-SESS-3 / FR-API-2/5), following the {@link RuleConfigService} exemplar.
 * Invalid config is rejected PRE-COMMIT ({@code 422}); a duplicate name / stale
 * version is a {@code 409}. Every mutation is audited atomically with the
 * write.
 */
@Service
public class SessionLimitPolicyConfigService {

	private static final String ORIGIN_API = "api";

	private final SessionLimitPolicyRepository policies;
	private final CursorPages cursorPages;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public SessionLimitPolicyConfigService(SessionLimitPolicyRepository policies, CursorPages cursorPages,
			AuditEventStore audit, TransactionalOperator tx) {
		this.policies = policies;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<SessionLimitPolicy>> list(String cursor, Integer limit) {
		return cursorPages.page(SessionLimitPolicy.class, Criteria.empty(), cursor, limit, SessionLimitPolicy::id);
	}

	public Mono<SessionLimitPolicy> get(UUID id) {
		return policies.findById(id)
				.switchIfEmpty(Mono.error(ApiProblemException.notFound("session-limit policy", id)));
	}

	public Mono<SessionLimitPolicy> create(String actor, String name, JsonNode identitySelector,
			Integer maxConcurrentSessions, Integer maxSessionSeconds, Integer idleTimeoutSeconds) {
		if (name == null || name.isBlank()) {
			throw ApiProblemException.validation("name must be non-blank");
		}
		validate(identitySelector, maxConcurrentSessions, maxSessionSeconds, idleTimeoutSeconds);
		SessionLimitPolicy policy = SessionLimitPolicy.create(name, identitySelector, maxConcurrentSessions,
				maxSessionSeconds, idleTimeoutSeconds, ORIGIN_API);
		return persist(null, policy, actor, "session_limit_policy.create", name);
	}

	public Mono<SessionLimitPolicy> update(UUID id, String actor, Long expectedVersion, JsonNode identitySelector,
			Integer maxConcurrentSessions, Integer maxSessionSeconds, Integer idleTimeoutSeconds) {
		validate(identitySelector, maxConcurrentSessions, maxSessionSeconds, idleTimeoutSeconds);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			SessionLimitPolicy updated = new SessionLimitPolicy(existing.id(), existing.name(), identitySelector,
					maxConcurrentSessions, maxSessionSeconds, idleTimeoutSeconds, ORIGIN_API, existing.version(),
					existing.createdAt(), existing.updatedAt());
			return persist(existing, updated, actor, "session_limit_policy.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		// Idempotent + auditable: capture the before-state, then delete + record the
		// change (before/after, FR-PADM-3); a delete of a missing row is still audited.
		return policies.findById(id).flatMap(before -> deleteWithAudit(id, actor, before))
				.switchIfEmpty(Mono.defer(() -> deleteWithAudit(id, actor, null)));
	}

	private Mono<Void> deleteWithAudit(UUID id, String actor, SessionLimitPolicy before) {
		return tx.transactional(policies.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "session_limit_policy.delete", Map.of(), before, null)));
	}

	private Mono<SessionLimitPolicy> persist(SessionLimitPolicy before, SessionLimitPolicy policy, String actor,
			String action, String name) {
		Mono<SessionLimitPolicy> body = policies.save(policy)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("name", name), before, saved)
						.thenReturn(saved));
		return tx.transactional(body).onErrorMap(OptimisticLockingFailureException.class,
				e -> ApiProblemException.conflict("the session-limit policy was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class, e -> ApiProblemException
						.conflict("a session-limit policy named '" + name + "' already exists"));
	}

	private static void validate(JsonNode identitySelector, Integer maxConcurrentSessions, Integer maxSessionSeconds,
			Integer idleTimeoutSeconds) {
		validateSelector(identitySelector);
		requirePositive("maxConcurrentSessions", maxConcurrentSessions);
		requirePositive("maxSessionSeconds", maxSessionSeconds);
		requirePositive("idleTimeoutSeconds", idleTimeoutSeconds);
		// An all-null policy is a no-op that silently enforces nothing — reject it
		// pre-commit (FR-SESS-3 "no dead config").
		if (maxConcurrentSessions == null && maxSessionSeconds == null && idleTimeoutSeconds == null) {
			throw ApiProblemException.validation(
					"at least one of maxConcurrentSessions/maxSessionSeconds/idleTimeoutSeconds must be set");
		}
	}

	// Stricter than the dp_rule surface on purpose: a selector shape the S5
	// evaluator quietly ignores (non-array/empty identities/groups, no all:true)
	// would select NO ONE — a silently-dead limit policy (FR-SESS-3 "no dead
	// config"). The evaluator-parse check still runs first so the accepted shapes
	// are exactly the ones Authorize resolves.
	private static void validateSelector(JsonNode selector) {
		if (selector == null || !selector.isObject()) {
			throw ApiProblemException.validation("identitySelector must be a JSON object");
		}
		SelectorValidation.identitySelector(selector);
		JsonNode all = selector.get("all");
		if (all != null && all.isBoolean() && all.booleanValue()) {
			return;
		}
		if (nonEmptyStringArray(selector.get("identities")) || nonEmptyStringArray(selector.get("groups"))) {
			return;
		}
		throw ApiProblemException.validation(
				"identitySelector must name a subject population: a non-empty identities/groups string array, or all:true");
	}

	private static boolean nonEmptyStringArray(JsonNode node) {
		if (node == null || !node.isArray() || node.isEmpty()) {
			return false;
		}
		for (JsonNode value : node.values()) {
			if (!value.isString()) {
				return false;
			}
		}
		return true;
	}

	private static void requirePositive(String field, Integer value) {
		if (value != null && value < 1) {
			throw ApiProblemException.validation(field + " must be >= 1");
		}
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
