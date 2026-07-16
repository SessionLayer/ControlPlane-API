package io.sessionlayer.controlplane.configapi;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.config.NodePolicy;
import io.sessionlayer.controlplane.data.config.NodePolicyRepository;
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
 * Config CRUD for node policies (`config.node_policy`, Design §12A). A
 * host-trust ref that carries inline private-key material is rejected
 * PRE-COMMIT ({@code 422}); a duplicate name / stale version is a {@code 409}.
 * Every mutation is audited atomically with the write. Mirrors
 * {@link RuleConfigService}.
 */
@Service
public class NodePolicyConfigService {

	private static final String ORIGIN_API = "api";

	private final NodePolicyRepository policies;
	private final CursorPages cursorPages;
	private final AuditWriter audit;
	private final TransactionalOperator tx;

	public NodePolicyConfigService(NodePolicyRepository policies, CursorPages cursorPages, AuditWriter audit,
			TransactionalOperator tx) {
		this.policies = policies;
		this.cursorPages = cursorPages;
		this.audit = audit;
		this.tx = tx;
	}

	public Mono<CursorPages.Page<NodePolicy>> list(String cursor, Integer limit) {
		return cursorPages.page(NodePolicy.class, Criteria.empty(), cursor, limit, NodePolicy::id);
	}

	public Mono<NodePolicy> get(UUID id) {
		return policies.findById(id).switchIfEmpty(Mono.error(ApiProblemException.notFound("node policy", id)));
	}

	public Mono<NodePolicy> create(String actor, String name, JsonNode desiredLabels, String connectorKind,
			String hostPinRef, String hostCaRef) {
		validate(hostPinRef, hostCaRef);
		NodePolicy policy = NodePolicy.create(name, desiredLabels, connectorKind, hostPinRef, hostCaRef, ORIGIN_API);
		return persist(policy, actor, "node_policy.create", name);
	}

	public Mono<NodePolicy> update(UUID id, String actor, Long expectedVersion, JsonNode desiredLabels,
			String connectorKind, String hostPinRef, String hostCaRef) {
		validate(hostPinRef, hostCaRef);
		return get(id).flatMap(existing -> {
			requireVersion(expectedVersion, existing.version());
			NodePolicy updated = new NodePolicy(existing.id(), existing.name(), desiredLabels, connectorKind,
					hostPinRef, hostCaRef, ORIGIN_API, existing.version(), existing.createdAt(), existing.updatedAt());
			return persist(updated, actor, "node_policy.update", existing.name());
		});
	}

	public Mono<Void> delete(UUID id, String actor) {
		return tx.transactional(policies.deleteById(id)
				.then(audit.record(actor, id.toString(), "node_policy.delete", "success", null, null, Map.of())));
	}

	private Mono<NodePolicy> persist(NodePolicy policy, String actor, String action, String name) {
		Mono<NodePolicy> body = policies.save(policy)
				.flatMap(saved -> audit
						.record(actor, saved.id().toString(), action, "success", null, null, Map.of("name", name))
						.thenReturn(saved));
		return tx.transactional(body)
				.onErrorMap(OptimisticLockingFailureException.class,
						e -> ApiProblemException.conflict("the node policy was modified concurrently (stale version)"))
				.onErrorMap(DataIntegrityViolationException.class,
						e -> ApiProblemException.conflict("a node policy named '" + name + "' already exists"));
	}

	// Host-trust refs are POINTERS (a pin digest / CA name), never inline key
	// material (Design §12A) — reject anything that looks like a private key.
	private static void validate(String hostPinRef, String hostCaRef) {
		rejectPrivateKey(hostPinRef, "hostPinRef");
		rejectPrivateKey(hostCaRef, "hostCaRef");
	}

	private static void rejectPrivateKey(String ref, String field) {
		if (ref != null && ref.contains("PRIVATE KEY")) {
			throw ApiProblemException.validation(field + " must be a reference, not private key material");
		}
	}

	private static void requireVersion(Long expected, Long actual) {
		if (expected != null && !expected.equals(actual)) {
			throw ApiProblemException.conflict("stale version " + expected + " (current " + actual + ")");
		}
	}
}
