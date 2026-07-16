package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
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
 * Config CRUD for platform role bindings (`config.role_binding`, FR-PADM-2). A
 * binding whose {@code roleId} references no {@code platform_role} is rejected
 * PRE-COMMIT ({@code 422}); a duplicate (roleId, subjectKind, subject) / stale
 * version is a {@code 409}. Subject and role are immutable — only {@code scope}
 * updates. Every mutation is audited atomically with the write. Mirrors
 * {@link RuleConfigService}.
 */
@Service
public class RoleBindingConfigService {

	private static final String ORIGIN_API = "api";

	private final RoleBindingRepository bindings;
	private final PlatformRoleRepository roles;
	private final CursorPages cursorPages;
	private final AuditWriter audit;
	private final TransactionalOperator tx;

	public RoleBindingConfigService(RoleBindingRepository bindings, PlatformRoleRepository roles,
			CursorPages cursorPages, AuditWriter audit, TransactionalOperator tx) {
		this.bindings = bindings;
		this.roles = roles;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<RoleBinding>> list(String cursor, Integer limit) {
		return cursorPages.page(RoleBinding.class, Criteria.empty(), cursor, limit, RoleBinding::id);
	}

	public Mono<RoleBinding> get(UUID id) {
		return bindings.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("role binding", id)));
	}

	public Mono<RoleBinding> create(String actor, UUID roleId, String subjectKind, String subject, JsonNode scope) {
		return requireRole(roleId)
				.then(persist(null, RoleBinding.create(roleId, subjectKind, subject, scope, ORIGIN_API), actor,
						"role_binding.create", subject));
	}

	public Mono<RoleBinding> update(UUID id, String actor, Long expectedVersion, JsonNode scope) {
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			RoleBinding updated = new RoleBinding(existing.id(), existing.roleId(), existing.subjectKind(),
					existing.subject(), scope, ORIGIN_API, existing.version(), existing.createdAt(),
					existing.updatedAt());
			return persist(existing, updated, actor, "role_binding.update", existing.subject());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		return bindings.findById(id).flatMap(before -> deleteWithAudit(id, actor, before))
				.switchIfEmpty(Mono.defer(() -> deleteWithAudit(id, actor, null)));
	}

	private Mono<Void> deleteWithAudit(UUID id, String actor, RoleBinding before) {
		return tx.transactional(bindings.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "role_binding.delete", Map.of(), before, null)));
	}

	// The role FK is validated pre-commit for a clean 422; a lost race with a
	// concurrent role delete is the DB's FK constraint (surfaced as a 409).
	private Mono<PlatformRole> requireRole(UUID roleId) {
		return roles.findById(roleId)
				.switchIfEmpty(Mono.error(ApiProblemException.validation("unknown roleId " + roleId)));
	}

	private Mono<RoleBinding> persist(RoleBinding before, RoleBinding binding, String actor, String action,
			String subject) {
		Mono<RoleBinding> body = bindings.save(binding)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("subject", subject), before, saved)
						.thenReturn(saved));
		return tx.transactional(body)
				.onErrorMap(OptimisticLockingFailureException.class,
						e -> ApiProblemException.conflict("the role binding was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class, e -> ApiProblemException
						.conflict("a binding for subject '" + subject + "' on this role already exists"));
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
