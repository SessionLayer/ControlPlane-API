package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.CursorPages;
import java.util.List;
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
 * Config CRUD for data-plane rules (`config.dp_rule`, FR-API-2/5). Invalid
 * config is rejected PRE-COMMIT ({@code 422}); a duplicate name / stale version
 * is a {@code 409}. Every mutation is audited atomically with the write. The
 * exemplar the other Session 17 config services follow.
 */
@Service
public class RuleConfigService {

	private static final String ORIGIN_API = "api";

	private final DpRuleRepository rules;
	private final CursorPages cursorPages;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public RuleConfigService(DpRuleRepository rules, CursorPages cursorPages, AuditEventStore audit,
			TransactionalOperator tx) {
		this.rules = rules;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<DpRule>> list(String cursor, Integer limit) {
		return cursorPages.page(DpRule.class, Criteria.empty(), cursor, limit, DpRule::id);
	}

	public Mono<DpRule> get(UUID id) {
		return rules.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("rule", id)));
	}

	public Mono<DpRule> create(String actor, String name, JsonNode identitySelector, JsonNode nodeLabelSelector,
			JsonNode sourceIpCondition, List<String> principals, int ttlSeconds, List<String> capabilities,
			String effect) {
		validate(ttlSeconds, principals, identitySelector, nodeLabelSelector, sourceIpCondition);
		DpRule rule = DpRule.create(name, identitySelector, nodeLabelSelector, sourceIpCondition, principals,
				ttlSeconds, capabilities, effect, ORIGIN_API);
		return persist(null, rule, actor, "rule.create", name);
	}

	public Mono<DpRule> update(UUID id, String actor, Long expectedVersion, JsonNode identitySelector,
			JsonNode nodeLabelSelector, JsonNode sourceIpCondition, List<String> principals, int ttlSeconds,
			List<String> capabilities, String effect) {
		validate(ttlSeconds, principals, identitySelector, nodeLabelSelector, sourceIpCondition);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			DpRule updated = new DpRule(existing.id(), existing.name(), identitySelector, nodeLabelSelector,
					sourceIpCondition, principals, ttlSeconds, capabilities, effect, ORIGIN_API, existing.version(),
					existing.createdAt(), existing.updatedAt());
			return persist(existing, updated, actor, "rule.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		// Idempotent + auditable: capture the before-state, then delete + record the
		// change (before/after, FR-PADM-3); a delete of a missing row is still audited.
		return rules.findById(id).flatMap(before -> deleteWithAudit(id, actor, before))
				.switchIfEmpty(Mono.defer(() -> deleteWithAudit(id, actor, null)));
	}

	private Mono<Void> deleteWithAudit(UUID id, String actor, DpRule before) {
		return tx.transactional(rules.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "rule.delete", Map.of(), before, null)));
	}

	private Mono<DpRule> persist(DpRule before, DpRule rule, String actor, String action, String name) {
		Mono<DpRule> body = rules.save(rule)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("name", name), before, saved)
						.thenReturn(saved));
		return tx.transactional(body)
				.onErrorMap(OptimisticLockingFailureException.class,
						e -> ApiProblemException.conflict("the rule was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class,
						e -> ApiProblemException.conflict("a rule named '" + name + "' already exists"));
	}

	private static void validate(int ttlSeconds, List<String> principals, JsonNode identitySelector,
			JsonNode nodeLabelSelector, JsonNode sourceIpCondition) {
		if (ttlSeconds <= 0) {
			throw ApiProblemException.validation("ttlSeconds must be > 0");
		}
		if (principals == null || principals.isEmpty()) {
			throw ApiProblemException.validation("principals must be non-empty");
		}
		// Reject a selector the S5 evaluator can't parse pre-commit, so a malformed
		// rule
		// never persists to fail-closed (or worse) on the decision path.
		SelectorValidation.identitySelector(identitySelector);
		SelectorValidation.labelSelector(nodeLabelSelector, "nodeLabelSelector");
		SelectorValidation.sourceIpCondition(sourceIpCondition);
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
