package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
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
	private final CursorPages cursorPages;
	private final AuditWriter audit;
	private final TransactionalOperator tx;

	public RoleConfigService(PlatformRoleRepository roles, CursorPages cursorPages, AuditWriter audit,
			TransactionalOperator tx) {
		this.roles = roles;
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
		return persist(role, actor, "role.create", name);
	}

	public Mono<PlatformRole> update(UUID id, String actor, Long expectedVersion, List<String> permissions,
			String description) {
		validate(permissions);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			PlatformRole updated = new PlatformRole(existing.id(), existing.name(), permissions, description,
					ORIGIN_API, existing.version(), existing.createdAt(), existing.updatedAt());
			return persist(updated, actor, "role.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		// Idempotent: audit + delete whether or not the row existed.
		return tx.transactional(roles.deleteById(id)
				.then(audit.record(actor, id.toString(), "role.delete", "success", null, null, Map.of())));
	}

	private Mono<PlatformRole> persist(PlatformRole role, String actor, String action, String name) {
		Mono<PlatformRole> body = roles.save(role)
				.flatMap(saved -> audit
						.record(actor, saved.id().toString(), action, "success", null, null, Map.of("name", name))
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
