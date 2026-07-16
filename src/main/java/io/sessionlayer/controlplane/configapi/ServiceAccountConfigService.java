package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
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
 * Config CRUD for service-account <b>definitions</b> (`config.service_account`,
 * FR-AUTH-12). Issued credentials are RUNTIME and live under
 * {@code /v1/service-accounts/{id}/credentials} (AuthController); this surface
 * is the definition only and never accepts or returns a secret — a
 * {@code keyReference} that looks like private material, or a non-positive
 * {@code tokenTtlSeconds}, is rejected pre-commit as {@code 422}.
 */
@Service
public class ServiceAccountConfigService {

	private static final String ORIGIN_API = "api";
	private static final String DEFAULT_AUTH_METHOD = "private_key_jwt";

	private final ServiceAccountRepository accounts;
	private final CursorPages cursorPages;
	private final AuditWriter audit;
	private final TransactionalOperator tx;

	public ServiceAccountConfigService(ServiceAccountRepository accounts, CursorPages cursorPages, AuditWriter audit,
			TransactionalOperator tx) {
		this.accounts = accounts;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<ServiceAccount>> list(String cursor, Integer limit) {
		return cursorPages.page(ServiceAccount.class, Criteria.empty(), cursor, limit, ServiceAccount::id);
	}

	public Mono<ServiceAccount> get(UUID id) {
		return accounts.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("service account", id)));
	}

	public Mono<ServiceAccount> create(String actor, String name, String description, String authMethod,
			String keyReference, Integer tokenTtlSeconds) {
		validate(keyReference, tokenTtlSeconds);
		// auth_method is NOT NULL in the schema; default it when the request omits it.
		ServiceAccount account = ServiceAccount.create(name, description,
				authMethod == null ? DEFAULT_AUTH_METHOD : authMethod, keyReference, tokenTtlSeconds, ORIGIN_API);
		return persist(null, account, actor, "service_account.create", name);
	}

	public Mono<ServiceAccount> update(UUID id, String actor, Long expectedVersion, String description,
			String authMethod, String keyReference, Integer tokenTtlSeconds) {
		validate(keyReference, tokenTtlSeconds);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			// name is immutable; a PUT that omits the (NOT NULL) authMethod keeps it.
			ServiceAccount updated = new ServiceAccount(existing.id(), existing.name(), description,
					authMethod == null ? existing.authMethod() : authMethod, keyReference, tokenTtlSeconds, ORIGIN_API,
					existing.version(), existing.createdAt(), existing.updatedAt());
			return persist(existing, updated, actor, "service_account.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		return accounts.findById(id).flatMap(before -> deleteWithAudit(id, actor, before))
				.switchIfEmpty(Mono.defer(() -> deleteWithAudit(id, actor, null)));
	}

	private Mono<Void> deleteWithAudit(UUID id, String actor, ServiceAccount before) {
		return tx.transactional(accounts.deleteById(id)
				.then(audit.recordChange(actor, id.toString(), "service_account.delete", Map.of(), before, null)));
	}

	private Mono<ServiceAccount> persist(ServiceAccount before, ServiceAccount account, String actor, String action,
			String name) {
		Mono<ServiceAccount> body = accounts.save(account)
				.flatMap(saved -> audit
						.recordChange(actor, saved.id().toString(), action, Map.of("name", name), before, saved)
						.thenReturn(saved));
		return tx.transactional(body).onErrorMap(OptimisticLockingFailureException.class,
				e -> ApiProblemException.conflict("the service account was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class,
						e -> ApiProblemException.conflict("a service account named '" + name + "' already exists"));
	}

	private static void validate(String keyReference, Integer tokenTtlSeconds) {
		if (keyReference != null && keyReference.contains("PRIVATE KEY")) {
			throw ApiProblemException.validation("keyReference must be a public reference, not private material");
		}
		if (tokenTtlSeconds != null && tokenTtlSeconds <= 0) {
			throw ApiProblemException.validation("tokenTtlSeconds must be > 0");
		}
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
