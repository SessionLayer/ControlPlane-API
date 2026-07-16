package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
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

/**
 * Config CRUD for platform-RBAC roles (`config.platform_role`, FR-PADM-1). A
 * role with no permissions is rejected PRE-COMMIT ({@code 422}); a duplicate
 * name / stale version is a {@code 409}. Every mutation is audited atomically
 * with the write. Mirrors {@link RuleConfigService}.
 */
@Service
public class RoleConfigService {

	private static final String ORIGIN_API = "api";

	private final PlatformRoleRepository roles;
	private final RoleBindingRepository bindings;
	private final CursorPages cursorPages;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public RoleConfigService(PlatformRoleRepository roles, RoleBindingRepository bindings, CursorPages cursorPages,
			AuditEventStore audit, TransactionalOperator tx) {
		this.roles = roles;
		this.bindings = bindings;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<PlatformRole>> list(String cursor, Integer limit) {
		return cursorPages.page(PlatformRole.class, Criteria.empty(), cursor, limit, PlatformRole::id);
	}

	public Mono<PlatformRole> get(UUID id) {
		return roles.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("role", id)));
	}

	public Mono<PlatformRole> create(String actor, String name, List<String> permissions, String description) {
		validate(permissions);
		PlatformRole role = PlatformRole.create(name, permissions, description, ORIGIN_API);
		return persist(null, role, actor, "role.create", name);
	}

	public Mono<PlatformRole> update(UUID id, String actor, Long expectedVersion, List<String> permissions,
			String description) {
		validate(permissions);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			PlatformRole updated = new PlatformRole(existing.id(), existing.name(), permissions, description,
					ORIGIN_API, existing.version(), existing.createdAt(), existing.updatedAt());
			return persist(existing, updated, actor, "role.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		// Idempotent + auditable: a role delete CASCADEs its bindings (V2), so capture
		// the role before-state AND the cascaded binding ids in the audit (FR-PADM-3).
		return roles.findById(id)
				.flatMap(role -> bindings.findByRoleId(id).map(b -> b.id().toString()).collectList()
						.flatMap(cascaded -> deleteWithAudit(id, actor, role, cascaded)))
				.switchIfEmpty(Mono.defer(() -> deleteWithAudit(id, actor, null, List.of())));
	}

	private Mono<Void> deleteWithAudit(UUID id, String actor, PlatformRole before, List<String> cascadedBindings) {
		Map<String, String> detail = cascadedBindings.isEmpty()
				? Map.of()
				: Map.of("cascaded_bindings", String.join(",", cascadedBindings));
		return tx.transactional(roles.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "role.delete", detail, before, null)));
	}

	private Mono<PlatformRole> persist(PlatformRole before, PlatformRole role, String actor, String action,
			String name) {
		Mono<PlatformRole> body = roles.save(role)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("name", name), before, saved)
						.thenReturn(saved));
		return tx.transactional(body)
				.onErrorMap(OptimisticLockingFailureException.class,
						e -> ApiProblemException.conflict("the role was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class,
						e -> ApiProblemException.conflict("a role named '" + name + "' already exists"));
	}

	private static void validate(List<String> permissions) {
		if (permissions == null || permissions.isEmpty()) {
			throw ApiProblemException.validation("permissions must be non-empty");
		}
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
