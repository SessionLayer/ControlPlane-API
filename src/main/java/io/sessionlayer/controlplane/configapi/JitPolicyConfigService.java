package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.config.JitPolicy;
import io.sessionlayer.controlplane.data.config.JitPolicyRepository;
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
 * Config CRUD for JIT-access policies (`config.jit_policy`, FR-ACC-3). A
 * non-positive {@code maxTtlSeconds} or an approval level with a blank value is
 * rejected PRE-COMMIT ({@code 422}); a duplicate name / stale version is a
 * {@code 409}. Every mutation is audited atomically with the write. Mirrors
 * {@link RuleConfigService}.
 */
@Service
public class JitPolicyConfigService {

	private static final String ORIGIN_API = "api";

	private final JitPolicyRepository policies;
	private final CursorPages cursorPages;
	private final AuditWriter audit;
	private final TransactionalOperator tx;

	public JitPolicyConfigService(JitPolicyRepository policies, CursorPages cursorPages, AuditWriter audit,
			TransactionalOperator tx) {
		this.policies = policies;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<JitPolicy>> list(String cursor, Integer limit) {
		return cursorPages.page(JitPolicy.class, Criteria.empty(), cursor, limit, JitPolicy::id);
	}

	public Mono<JitPolicy> get(UUID id) {
		return policies.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("jit policy", id)));
	}

	public Mono<JitPolicy> create(String actor, String name, JsonNode targetSelector, List<String> capabilities,
			int maxTtlSeconds, JsonNode approvalChain) {
		validate(maxTtlSeconds, targetSelector, approvalChain);
		JitPolicy policy = JitPolicy.create(name, targetSelector, capabilities, maxTtlSeconds, approvalChain,
				ORIGIN_API);
		return persist(null, policy, actor, "jit_policy.create", name);
	}

	public Mono<JitPolicy> update(UUID id, String actor, Long expectedVersion, JsonNode targetSelector,
			List<String> capabilities, int maxTtlSeconds, JsonNode approvalChain) {
		validate(maxTtlSeconds, targetSelector, approvalChain);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			JitPolicy updated = new JitPolicy(existing.id(), existing.name(), targetSelector, capabilities,
					maxTtlSeconds, approvalChain, ORIGIN_API, existing.version(), existing.createdAt(),
					existing.updatedAt());
			return persist(existing, updated, actor, "jit_policy.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		return policies.findById(id).flatMap(before -> deleteWithAudit(id, actor, before))
				.switchIfEmpty(Mono.defer(() -> deleteWithAudit(id, actor, null)));
	}

	private Mono<Void> deleteWithAudit(UUID id, String actor, JitPolicy before) {
		return tx.transactional(policies.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "jit_policy.delete", Map.of(), before, null)));
	}

	private Mono<JitPolicy> persist(JitPolicy before, JitPolicy policy, String actor, String action, String name) {
		Mono<JitPolicy> body = policies.save(policy)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("name", name), before, saved)
						.thenReturn(saved));
		return tx.transactional(body)
				.onErrorMap(OptimisticLockingFailureException.class,
						e -> ApiProblemException.conflict("the jit policy was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class,
						e -> ApiProblemException.conflict("a jit policy named '" + name + "' already exists"));
	}

	// The approval-chain length ceiling (<= 3) is a bean-validation 400; here we
	// reject the semantic gaps a schema cannot catch (FR-ACC-3): a non-positive TTL
	// and an approval level with no addressable value.
	private static void validate(int maxTtlSeconds, JsonNode targetSelector, JsonNode approvalChain) {
		if (maxTtlSeconds <= 0) {
			throw ApiProblemException.validation("maxTtlSeconds must be > 0");
		}
		// The JIT-request submit path label-matches this selector against a node; a
		// shape the evaluator can't parse would break submit, so reject it pre-commit.
		SelectorValidation.labelSelector(targetSelector, "targetSelector");
		if (approvalChain != null && approvalChain.isArray()) {
			for (JsonNode level : approvalChain) {
				JsonNode value = level.get("value");
				if (value == null || !value.isString() || value.stringValue().isBlank()) {
					throw ApiProblemException.validation("each approval level must have a non-blank value");
				}
			}
		}
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
