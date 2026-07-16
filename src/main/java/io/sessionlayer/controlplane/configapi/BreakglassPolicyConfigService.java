package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.config.BreakglassPolicy;
import io.sessionlayer.controlplane.data.config.BreakglassPolicyRepository;
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

/**
 * Config CRUD for break-glass policies (`config.breakglass_policy`, FR-ACC-6).
 * A duplicate name / stale version is a {@code 409}. Booleans and the auth path
 * are coalesced to their fail-safe defaults by the controller before they reach
 * here. Every mutation is audited atomically with the write. Mirrors
 * {@link RuleConfigService}.
 */
@Service
public class BreakglassPolicyConfigService {

	private static final String ORIGIN_API = "api";

	private final BreakglassPolicyRepository policies;
	private final CursorPages cursorPages;
	private final AuditWriter audit;
	private final TransactionalOperator tx;

	public BreakglassPolicyConfigService(BreakglassPolicyRepository policies, CursorPages cursorPages,
			AuditWriter audit, TransactionalOperator tx) {
		this.policies = policies;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<BreakglassPolicy>> list(String cursor, Integer limit) {
		return cursorPages.page(BreakglassPolicy.class, Criteria.empty(), cursor, limit, BreakglassPolicy::id);
	}

	public Mono<BreakglassPolicy> get(UUID id) {
		return policies.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("breakglass policy", id)));
	}

	public Mono<BreakglassPolicy> create(String actor, String name, boolean recordingStrict, String alertTarget,
			boolean reviewRequired, String authPath) {
		BreakglassPolicy policy = BreakglassPolicy.create(name, recordingStrict, alertTarget, reviewRequired, authPath,
				ORIGIN_API);
		return persist(null, policy, actor, "breakglass_policy.create", name);
	}

	public Mono<BreakglassPolicy> update(UUID id, String actor, Long expectedVersion, boolean recordingStrict,
			String alertTarget, boolean reviewRequired, String authPath) {
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			BreakglassPolicy updated = new BreakglassPolicy(existing.id(), existing.name(), recordingStrict,
					alertTarget, reviewRequired, authPath, ORIGIN_API, existing.version(), existing.createdAt(),
					existing.updatedAt());
			return persist(existing, updated, actor, "breakglass_policy.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		return policies.findById(id).flatMap(before -> deleteWithAudit(id, actor, before))
				.switchIfEmpty(Mono.defer(() -> deleteWithAudit(id, actor, null)));
	}

	private Mono<Void> deleteWithAudit(UUID id, String actor, BreakglassPolicy before) {
		return tx.transactional(policies.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "breakglass_policy.delete", Map.of(), before, null)));
	}

	private Mono<BreakglassPolicy> persist(BreakglassPolicy before, BreakglassPolicy policy, String actor,
			String action, String name) {
		Mono<BreakglassPolicy> body = policies.save(policy)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("name", name), before, saved)
						.thenReturn(saved));
		return tx.transactional(body).onErrorMap(OptimisticLockingFailureException.class,
				e -> ApiProblemException.conflict("the breakglass policy was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class,
						e -> ApiProblemException.conflict("a breakglass policy named '" + name + "' already exists"));
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
