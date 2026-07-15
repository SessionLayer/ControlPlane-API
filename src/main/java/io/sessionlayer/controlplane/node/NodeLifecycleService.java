package io.sessionlayer.controlplane.node;

import io.sessionlayer.controlplane.agent.AgentNodeNames;
import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeHostKey;
import io.sessionlayer.controlplane.data.runtime.NodeHostKeyRepository;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.LockFeedHub;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Node lifecycle (Design §9/§12A; FR-NODE-1/2/3). Agentless enrollment,
 * quarantine (expressed as a top-tier S10 Lock on the node, deny wins),
 * release, soft-remove, and listing. Every mutation is one transaction (state +
 * lock + audit) and any lock delta is pushed to Gateways via
 * {@link LockFeedHub} <b>after</b> commit (mirrors
 * {@code io.sessionlayer.controlplane.web.LockController}), so a Gateway can
 * never be pushed a lock a rolled-back transaction never stored.
 *
 * <p>
 * Agentless enrollment is never TOFU (§9.3): the node must present at least one
 * enrollment-anchored host identity — a host-CA-signed host certificate or an
 * explicitly pinned host key. Removing an <b>agent</b> node also revokes its
 * mTLS credential (flip off {@code active} + a covering Lock) so a stale clone
 * cannot ride the removed node's name.
 */
@Service
public class NodeLifecycleService {

	private static final String CONNECTOR_AGENTLESS = "agentless";
	private static final String STATUS_ACTIVE = "active";
	private static final String STATUS_PENDING = "pending";
	private static final String STATUS_QUARANTINED = "quarantined";
	private static final String STATUS_REMOVED = "removed";
	private static final String HEALTH_UNKNOWN = "unknown";
	private static final String REVOKE_REASON = "node removed (credential revoked)";

	private final NodeRepository nodes;
	private final NodeHostKeyRepository hostKeys;
	private final AgentIdentityRepository agentIdentities;
	private final AccessLockRepository accessLocks;
	private final LockFeedHub lockFeedHub;
	private final AuditWriter audit;
	private final ObjectMapper objectMapper;
	private final TransactionalOperator tx;

	public NodeLifecycleService(NodeRepository nodes, NodeHostKeyRepository hostKeys,
			AgentIdentityRepository agentIdentities, AccessLockRepository accessLocks, LockFeedHub lockFeedHub,
			AuditWriter audit, ObjectMapper objectMapper, TransactionalOperator tx) {
		this.nodes = nodes;
		this.hostKeys = hostKeys;
		this.agentIdentities = agentIdentities;
		this.accessLocks = accessLocks;
		this.lockFeedHub = lockFeedHub;
		this.audit = audit;
		this.objectMapper = objectMapper;
		this.tx = tx;
	}

	// ----- register -----

	public Mono<Node> registerAgentless(String name, String address, JsonNode labels, String hostCertificateLine,
			String pinnedHostKeyLine, String nodePolicyName, boolean approvalRequired, String actor) {
		NodeRequestException rejection = validateRegistration(name, address, hostCertificateLine, pinnedHostKeyLine);
		if (rejection != null) {
			return Mono.error(rejection);
		}
		JsonNode resolvedLabels = (labels == null) ? objectMapper.createObjectNode() : labels;
		String status = approvalRequired ? STATUS_PENDING : STATUS_ACTIVE;
		Node node = Node.create(name, blankToNull(nodePolicyName), resolvedLabels, CONNECTOR_AGENTLESS, status,
				HEALTH_UNKNOWN, null, address.trim());
		Mono<Node> persisted = nodes.save(node)
				.flatMap(saved -> saveHostAnchors(saved.id(), hostCertificateLine, pinnedHostKeyLine)
						.then(audit.record(actor, saved.id().toString(), "node.register", "success", null, saved.id(),
								Map.of("name", name, "connector", CONNECTOR_AGENTLESS, "status", status)))
						.thenReturn(saved));
		// The unique(name) constraint is the race-safe dedup — a concurrent duplicate
		// insert surfaces as a CONFLICT rather than a pre-check TOCTOU.
		return tx.transactional(persisted).onErrorMap(DuplicateKeyException.class,
				dup -> conflict("a node named '" + name + "' is already registered"));
	}

	private Mono<Void> saveHostAnchors(UUID nodeId, String hostCertificateLine, String pinnedHostKeyLine) {
		Flux<NodeHostKey> rows = Flux.empty();
		if (!isBlank(hostCertificateLine)) {
			String line = hostCertificateLine.trim();
			rows = rows.concatWith(
					Mono.just(NodeHostKey.create(nodeId, keyTypeOf(line), null, null, line, "host_ca", null)));
		}
		if (!isBlank(pinnedHostKeyLine)) {
			String line = pinnedHostKeyLine.trim();
			rows = rows.concatWith(Mono.just(
					NodeHostKey.create(nodeId, keyTypeOf(line), line, fingerprintOf(line), null, "pinned_key", null)));
		}
		return rows.concatMap(hostKeys::save).then();
	}

	// ----- quarantine -----

	public Mono<Node> quarantine(UUID nodeId, String reason, String existingSessions, Long ttlSeconds, String actor) {
		if (isBlank(reason)) {
			return Mono.error(invalid("a quarantine reason is required"));
		}
		if (ttlSeconds != null && (ttlSeconds <= 0 || ttlSeconds > Integer.MAX_VALUE)) {
			return Mono.error(invalid("ttlSeconds must be a positive number of seconds"));
		}
		// kill (default) tears sessions down at once → a strict lock; drain lets them
		// finish with no new channels → best_effort (Design §8.4 / FR-NODE-3).
		boolean drain = "drain".equals(existingSessions);
		String mode = drain ? "best_effort" : "strict";
		String policy = drain ? "drain" : "kill";
		Integer ttl = ttlSeconds == null ? null : ttlSeconds.intValue();
		Instant now = Instant.now();
		Instant expiresAt = ttl == null ? null : now.plusSeconds(ttl);
		return nodes.findById(nodeId).switchIfEmpty(Mono.error(notFound(nodeId))).flatMap(node -> {
			Node quarantined = withStatus(node, STATUS_QUARANTINED, reason, actor, now);
			AccessLock lock = AccessLock.create(nodeSelector(nodeId), mode, ttl, expiresAt, reason, actor);
			Mono<Tuple2<Node, AccessLock>> committed = tx
					.transactional(nodes.save(quarantined)
							.flatMap(savedNode -> accessLocks.save(lock).flatMap(savedLock -> audit
									.record(actor, nodeId.toString(), "node.quarantine", "success", null, nodeId,
											Map.of("reason", reason, "existing_sessions", policy, "lock_id",
													savedLock.id().toString()))
									.thenReturn(Tuples.of(savedNode, savedLock)))));
			return committed.doOnNext(t -> lockFeedHub.publishAdded(t.getT2())).map(Tuple2::getT1);
		});
	}

	public Mono<Node> releaseQuarantine(UUID nodeId, String actor) {
		Instant now = Instant.now();
		return nodes.findById(nodeId).switchIfEmpty(Mono.error(notFound(nodeId)))
				.flatMap(node -> accessLocks.findAll()
						.filter(lock -> isNodeQuarantineLock(lock.targetSelector(), nodeId)).collectList()
						.flatMap(locks -> releaseWith(node, locks, actor, now)));
	}

	private Mono<Node> releaseWith(Node node, List<AccessLock> locks, String actor, Instant now) {
		// Idempotent: whether or not the node was quarantined, clear any bare
		// node-quarantine lock(s) and return the node to active. A release NEVER
		// resurrects a torn-down session.
		Node active = STATUS_QUARANTINED.equals(node.status())
				? withStatus(node, STATUS_ACTIVE, "quarantine released", actor, now)
				: node;
		Mono<List<UUID>> committed = tx.transactional(Flux.fromIterable(locks)
				.concatMap(lock -> accessLocks.deleteById(lock.id()).thenReturn(lock.id())).collectList()
				.flatMap(removed -> nodes.save(active)
						.then(audit.record(actor, node.id().toString(), "node.quarantine.release", "success", null,
								node.id(), Map.of("locks_removed", Integer.toString(removed.size()))))
						.thenReturn(removed)));
		return committed.doOnNext(ids -> ids.forEach(lockFeedHub::publishRemoved)).thenReturn(active);
	}

	// ----- remove (soft) -----

	public Mono<Node> remove(UUID nodeId, String actor) {
		Instant now = Instant.now();
		// Idempotent: a node that never existed → no-op success (empty).
		return nodes.findById(nodeId).flatMap(node -> removeNode(nodeId, node, actor, now));
	}

	private Mono<Node> removeNode(UUID nodeId, Node node, String actor, Instant now) {
		if (STATUS_REMOVED.equals(node.status())) {
			return Mono.just(node); // already removed → no-op success
		}
		Node removed = withStatus(node, STATUS_REMOVED, "node removed", actor, now);
		Mono<Tuple2<Node, List<AccessLock>>> committed = tx.transactional(nodes.save(removed)
				.flatMap(savedNode -> revokeActiveAgentIdentity(savedNode, actor, now).flatMap(locks -> audit
						.record(actor, nodeId.toString(), "node.remove", "success", null, nodeId,
								Map.of("connector", savedNode.connectorKind()))
						.thenReturn(Tuples.of(savedNode, locks)))));
		return committed.doOnNext(t -> t.getT2().forEach(lockFeedHub::publishAdded)).map(Tuple2::getT1);
	}

	// Revoke the node's single active agent identity (partial unique index → at
	// most
	// one): flip off active and add a covering Lock carrying BOTH the node and the
	// agent-id facet (mirrors AgentRenewalService.autoLock) so the clone is refused
	// on
	// the session path AND on the agent control channel. Returns the lock(s) to
	// publish
	// after commit; empty for an agentless node (no identity).
	private Mono<List<AccessLock>> revokeActiveAgentIdentity(Node node, String actor, Instant now) {
		return agentIdentities.findByNodeIdAndStatus(node.id(), STATUS_ACTIVE).flatMap(identity -> {
			AgentIdentity revoked = new AgentIdentity(identity.id(), identity.nodeId(), identity.mtlsIdentityRef(),
					identity.fingerprint(), identity.prevFingerprint(), identity.generation(), identity.joinMethod(),
					"revoked", identity.issuedAt(), identity.notAfter(), REVOKE_REASON, actor, now, identity.version(),
					identity.createdAt(), identity.updatedAt());
			AccessLock lock = AccessLock.create(cloneLockSelector(node.id(), identity.id()), "strict", null, null,
					REVOKE_REASON, actor);
			return agentIdentities.save(revoked).then(accessLocks.save(lock))
					.flatMap(savedLock -> audit
							.record(actor, identity.id().toString(), "agent.revoke", "success", null, node.id(),
									Map.of("reason", REVOKE_REASON, "lock_id", savedLock.id().toString()))
							.thenReturn(List.of(savedLock)));
		}).defaultIfEmpty(List.of());
	}

	// ----- read -----

	public Flux<Node> list(boolean includeRemoved) {
		Flux<Node> all = nodes.findAll();
		return includeRemoved ? all : all.filter(node -> !STATUS_REMOVED.equals(node.status()));
	}

	public Mono<Node> get(UUID nodeId) {
		return nodes.findById(nodeId);
	}

	// ----- helpers -----

	private static Node withStatus(Node node, String status, String reason, String actor, Instant now) {
		return new Node(node.id(), node.name(), node.nodePolicyName(), node.resolvedLabels(), node.connectorKind(),
				status, node.health(), node.owningGateway(), node.address(), reason, actor, now, node.version(),
				node.createdAt(), node.updatedAt());
	}

	private ObjectNode nodeSelector(UUID nodeId) {
		ObjectNode selector = objectMapper.createObjectNode();
		selector.putArray("node_ids").add(nodeId.toString());
		return selector;
	}

	private ObjectNode cloneLockSelector(UUID nodeId, UUID agentId) {
		ObjectNode selector = objectMapper.createObjectNode();
		selector.putArray("node_ids").add(nodeId.toString());
		selector.putArray("identities").add(agentId.toString());
		return selector;
	}

	// A bare node-quarantine lock is exactly {"node_ids":[nodeId]} — node_ids is
	// the
	// only facet and names just this node. Requiring "no other facet" is
	// load-bearing:
	// it means a release NEVER lifts a clone-detection lock (which carries an
	// identities facet) or a multi-node incident lock, only the quarantine this API
	// created.
	private static boolean isNodeQuarantineLock(JsonNode selector, UUID nodeId) {
		if (selector == null || !selector.isObject()) {
			return false;
		}
		JsonNode nodeIds = selector.get("node_ids");
		if (nodeIds == null || !nodeIds.isArray() || nodeIds.size() != 1
				|| !nodeId.toString().equals(nodeIds.get(0).asString())) {
			return false;
		}
		for (String facet : List.of("identities", "groups", "principals", "node_labels")) {
			JsonNode values = selector.get(facet);
			if (values != null && values.isArray() && !values.isEmpty()) {
				return false;
			}
		}
		return !selector.path("all").asBoolean(false);
	}

	private NodeRequestException validateRegistration(String name, String address, String certLine, String pinLine) {
		if (!AgentNodeNames.isValid(name)) {
			return invalid("invalid node name");
		}
		if (isBlank(address)) {
			return invalid("a dial address is required");
		}
		boolean hasCert = !isBlank(certLine);
		boolean hasPin = !isBlank(pinLine);
		if (!hasCert && !hasPin) {
			// §9.3: never TOFU — an agentless node needs an enrollment-anchored host
			// identity (a host-CA cert or an explicitly pinned host key).
			return invalid("a host certificate or a pinned host key is required (no TOFU)");
		}
		NodeRequestException certRejection = hasCert ? badHostLine(certLine, "hostCertificate") : null;
		if (certRejection != null) {
			return certRejection;
		}
		return hasPin ? badHostLine(pinLine, "pinnedHostKey") : null;
	}

	// A host anchor line must be a real OpenSSH "<type> <base64>" line so a typo
	// can
	// never masquerade as trust (a malformed anchor would be silently dropped at
	// Authorize time, leaving the node un-dialable with a confusing failure).
	private static NodeRequestException badHostLine(String line, String field) {
		String[] fields = line.trim().split("\\s+");
		if (fields.length < 2) {
			return invalid("a " + field + " must be an OpenSSH \"<type> <base64>\" line");
		}
		try {
			Base64.getDecoder().decode(fields[1]);
		} catch (IllegalArgumentException notBase64) {
			return invalid("a " + field + " must carry a base64 key/cert blob");
		}
		return null;
	}

	private static String keyTypeOf(String openSshLine) {
		String[] fields = openSshLine.trim().split("\\s+");
		return fields.length > 0 ? fields[0] : "";
	}

	private static String fingerprintOf(String openSshLine) {
		String[] fields = openSshLine.trim().split("\\s+");
		if (fields.length < 2) {
			return null;
		}
		try {
			byte[] blob = Base64.getDecoder().decode(fields[1]);
			byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(blob);
			return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
		} catch (Exception malformed) {
			return null;
		}
	}

	private static String blankToNull(String value) {
		return isBlank(value) ? null : value.trim();
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	private static NodeRequestException invalid(String message) {
		return new NodeRequestException(NodeRequestException.Reason.INVALID_ARGUMENT, message);
	}

	private static NodeRequestException notFound(UUID nodeId) {
		return new NodeRequestException(NodeRequestException.Reason.NOT_FOUND, "node " + nodeId + " not found");
	}

	private static NodeRequestException conflict(String message) {
		return new NodeRequestException(NodeRequestException.Reason.CONFLICT, message);
	}
}
