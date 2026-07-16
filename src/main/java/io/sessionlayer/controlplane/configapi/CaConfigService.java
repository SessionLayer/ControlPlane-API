package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.ca.CaRotationService;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.web.ApiProblemException;
import io.sessionlayer.controlplane.web.CursorPages;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.relational.core.query.Criteria;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;

/**
 * Config CRUD for certificate authorities (`config.ca_config`, FR-CA-1/4/7).
 * Registers per-CA backend + key <b>reference</b> only — never private key
 * material (a {@code keyReference} that looks like a private key, or an
 * unsupported algorithm/backend pair, is rejected pre-commit as {@code 422}).
 * {@code rotate} drives the S3 local rotation state machine
 * ({@link CaRotationService}); this service never generates or handles key
 * material itself.
 *
 * <p>
 * The frozen contract's {@code CaKind} is {@code user|session|host}; the
 * internal mTLS CA (S4, kind {@code mtls}) is out of this surface, so
 * reads/writes are scoped to the three SSH-CA kinds and an {@code mtls} id is
 * {@code 404}.
 */
@Service
public class CaConfigService {

	private static final String ORIGIN_API = "api";
	private static final String ACTIVE = "active";

	/** Kinds this admin surface manages; the internal mTLS CA is excluded. */
	private static final Set<String> API_KINDS = Set.of("user", "session", "host");

	private final CaConfigRepository caConfigs;
	private final CaRotationService rotation;
	private final CursorPages cursorPages;
	private final AuditWriter audit;
	private final TransactionalOperator tx;

	public CaConfigService(CaConfigRepository caConfigs, CaRotationService rotation, CursorPages cursorPages,
			AuditWriter audit, TransactionalOperator tx) {
		this.caConfigs = caConfigs;
		this.rotation = rotation;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<CaConfig>> list(String cursor, Integer limit) {
		return cursorPages.page(CaConfig.class, Criteria.where("caKind").in(API_KINDS), cursor, limit, CaConfig::id);
	}

	public Mono<CaConfig> get(UUID id) {
		return caConfigs.findById(id).filter(ca -> API_KINDS.contains(ca.caKind()))
				.switchIfEmpty(Mono.error(ApiProblemException.notFound("ca", id)));
	}

	public Mono<CaConfig> create(String actor, String name, String caKind, String backend, String keyReference,
			String algorithm) {
		validate(backend, keyReference, algorithm);
		// rotationState is server-set: a newly registered CA is the active signer.
		CaConfig ca = CaConfig.create(name, caKind, backend, keyReference, algorithm, ACTIVE, ORIGIN_API);
		return persist(ca, actor, "ca.create", name);
	}

	public Mono<CaConfig> update(UUID id, String actor, Long expectedVersion, String backend, String keyReference,
			String algorithm) {
		validate(backend, keyReference, algorithm);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			// name/caKind are immutable and rotationState is owned by the rotation
			// machine (rotate), so only backend/keyReference/algorithm are replaced.
			CaConfig updated = new CaConfig(existing.id(), existing.name(), existing.caKind(), backend, keyReference,
					algorithm, existing.rotationState(), ORIGIN_API, existing.version(), existing.createdAt(),
					existing.updatedAt());
			return persist(updated, actor, "ca.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		return caConfigs.findById(id).flatMap(existing -> {
			if (!API_KINDS.contains(existing.caKind())) {
				return Mono.<Void>error(ApiProblemException.notFound("ca", id));
			}
			// A kind must always retain a signer: never delete the active CA (rotate
			// first).
			if (ACTIVE.equals(existing.rotationState())) {
				return Mono.<Void>error(ApiProblemException
						.conflict("cannot delete the active CA of kind '" + existing.caKind() + "' — rotate first"));
			}
			return deleteAndAudit(id, actor);
		}).switchIfEmpty(Mono.defer(() -> deleteAndAudit(id, actor)));
	}

	/**
	 * Rotate the CA <b>kind</b> of {@code id} through the local rotation state
	 * machine (FR-CA-7): provision a fresh incoming CA, promote it to active and
	 * demote the current active to outgoing (both trusted during the overlap), then
	 * return the new active CA. Never returns private material.
	 */
	public Mono<CaConfig> rotate(UUID id, String actor) {
		return get(id).flatMap(existing -> {
			String kind = existing.caKind();
			return rotation.beginRotation(kind, kind + "-" + UUID.randomUUID()).then(rotation.promote(kind))
					.then(caConfigs.findByCaKindAndRotationState(kind, ACTIVE))
					.flatMap(active -> audit.record(actor, active.id().toString(), "ca.rotate", "success", null, null,
							Map.of("kind", kind)).thenReturn(active));
		});
	}

	private Mono<Void> deleteAndAudit(UUID id, String actor) {
		return tx.transactional(caConfigs.deleteById(id)
				.then(audit.record(actor, id.toString(), "ca.delete", "success", null, null, Map.of())));
	}

	private Mono<CaConfig> persist(CaConfig ca, String actor, String action, String name) {
		Mono<CaConfig> body = caConfigs.save(ca)
				.flatMap(saved -> audit
						.record(actor, saved.id().toString(), action, "success", null, null, Map.of("name", name))
						.thenReturn(saved));
		return tx.transactional(body)
				.onErrorMap(OptimisticLockingFailureException.class,
						e -> ApiProblemException.conflict("the CA was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class, e -> ApiProblemException
						.conflict("a CA named '" + name + "' already exists, or its kind already has an active CA"));
	}

	private static void validate(String backend, String keyReference, String algorithm) {
		if (keyReference == null || keyReference.contains("PRIVATE KEY") || keyReference.contains("BEGIN ")) {
			throw ApiProblemException.validation("keyReference must be a backend key reference, not private material");
		}
		// Design D6: Azure Key Vault has no Ed25519 signing key type.
		if ("azure_keyvault".equals(backend) && "ed25519".equals(algorithm)) {
			throw ApiProblemException.validation("backend 'azure_keyvault' does not support algorithm 'ed25519'");
		}
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
