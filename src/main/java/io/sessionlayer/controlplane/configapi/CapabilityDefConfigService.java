package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.data.config.CapabilityDef;
import io.sessionlayer.controlplane.data.config.CapabilityDefRepository;
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
 * Config CRUD for the requestable-capability catalogue
 * (`config.capability_def`, Design §12A). The {@code name} is a fixed
 * capability enum (immutable once created); only {@code description} is
 * mutable. A duplicate name / stale version is a {@code 409}. Every mutation is
 * audited atomically with the write. Mirrors {@link RuleConfigService}.
 */
@Service
public class CapabilityDefConfigService {

	private static final String ORIGIN_API = "api";

	private final CapabilityDefRepository capabilities;
	private final CursorPages cursorPages;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;

	public CapabilityDefConfigService(CapabilityDefRepository capabilities, CursorPages cursorPages,
			AuditEventStore audit, TransactionalOperator tx) {
		this.capabilities = capabilities;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<CapabilityDef>> list(String cursor, Integer limit) {
		return cursorPages.page(CapabilityDef.class, Criteria.empty(), cursor, limit, CapabilityDef::id);
	}

	public Mono<CapabilityDef> get(UUID id) {
		return capabilities.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("capability def", id)));
	}

	public Mono<CapabilityDef> create(String actor, String name, String description) {
		CapabilityDef def = CapabilityDef.create(name, description, ORIGIN_API);
		return persist(null, def, actor, "capability_def.create", name);
	}

	public Mono<CapabilityDef> update(UUID id, String actor, Long expectedVersion, String description) {
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			CapabilityDef updated = new CapabilityDef(existing.id(), existing.name(), description, ORIGIN_API,
					existing.version(), existing.createdAt(), existing.updatedAt());
			return persist(existing, updated, actor, "capability_def.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		return capabilities.findById(id).flatMap(before -> deleteWithAudit(id, actor, before))
				.switchIfEmpty(Mono.defer(() -> deleteWithAudit(id, actor, null)));
	}

	private Mono<Void> deleteWithAudit(UUID id, String actor, CapabilityDef before) {
		return tx.transactional(capabilities.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "capability_def.delete", Map.of(), before, null)));
	}

	private Mono<CapabilityDef> persist(CapabilityDef before, CapabilityDef def, String actor, String action,
			String name) {
		Mono<CapabilityDef> body = capabilities.save(def)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("name", name), before, saved)
						.thenReturn(saved));
		return tx.transactional(body).onErrorMap(OptimisticLockingFailureException.class,
				e -> ApiProblemException.conflict("the capability def was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class,
						e -> ApiProblemException.conflict("a capability def named '" + name + "' already exists"));
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
