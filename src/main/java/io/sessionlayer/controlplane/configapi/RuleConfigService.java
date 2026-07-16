package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditWriter;
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
	private final AuditWriter audit;
	private final TransactionalOperator tx;

	public RuleConfigService(DpRuleRepository rules, CursorPages cursorPages, AuditWriter audit,
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
		validate(ttlSeconds, principals);
		DpRule rule = DpRule.create(name, identitySelector, nodeLabelSelector, sourceIpCondition, principals,
				ttlSeconds, capabilities, effect, ORIGIN_API);
		return persist(rule, actor, "rule.create", name);
	}

	public Mono<DpRule> update(UUID id, String actor, Long expectedVersion, JsonNode identitySelector,
			JsonNode nodeLabelSelector, JsonNode sourceIpCondition, List<String> principals, int ttlSeconds,
			List<String> capabilities, String effect) {
		validate(ttlSeconds, principals);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			DpRule updated = new DpRule(existing.id(), existing.name(), identitySelector, nodeLabelSelector,
					sourceIpCondition, principals, ttlSeconds, capabilities, effect, ORIGIN_API, existing.version(),
					existing.createdAt(), existing.updatedAt());
			return persist(updated, actor, "rule.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		// Idempotent: audit + delete whether or not the row existed.
		return tx.transactional(rules.deleteById(id)
				.then(audit.record(actor, id.toString(), "rule.delete", "success", null, null, Map.of())));
	}

	private Mono<DpRule> persist(DpRule rule, String actor, String action, String name) {
		Mono<DpRule> body = rules.save(rule)
				.flatMap(saved -> audit
						.record(actor, saved.id().toString(), action, "success", null, null, Map.of("name", name))
						.thenReturn(saved));
		return tx.transactional(body)
				.onErrorMap(OptimisticLockingFailureException.class,
						e -> ApiProblemException.conflict("the rule was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class,
						e -> ApiProblemException.conflict("a rule named '" + name + "' already exists"));
	}

	private static void validate(int ttlSeconds, List<String> principals) {
		if (ttlSeconds <= 0) {
			throw ApiProblemException.validation("ttlSeconds must be > 0");
		}
		if (principals == null || principals.isEmpty()) {
			throw ApiProblemException.validation("principals must be non-empty");
		}
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
