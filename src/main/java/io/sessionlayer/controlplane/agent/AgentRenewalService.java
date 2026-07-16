package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.Pkcs10Csrs;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.LockFeedHub;
import io.sessionlayer.controlplane.mtls.AgentIdentityUri;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Renews an Agent's mTLS identity (Part B, FR-JOIN-4). Authenticated by the
 * caller's current mTLS client certificate (resolved by the interceptor to
 * {@code callerAgentId}); a locked/revoked identity is refused. The CP issues
 * {@code current_generation + 1} and enforces monotonicity.
 *
 * <p>
 * The S12 escalation over S4: a declared generation that does not match the
 * stored one is treated as clone detection (§8.2) — the identity is
 * <b>auto-locked</b> (status flip + an {@code access_lock} covering the node,
 * pushed to live Gateways via the S10 feed), a distinct security alert is
 * raised, and the renewal is refused. Because the pin tolerates {current,
 * prev}, both the stale copy and the fork fail the generation check thereafter,
 * so both are locked; the lock <b>never auto-clears</b> (operator
 * re-provision). A concurrent renewal that loses the {@code @Version} race is
 * also a clone signal and takes the same auto-lock path.
 */
@Service
public class AgentRenewalService {

	private static final String CLONE_REASON = "generation mismatch (possible credential clone)";
	private static final String CLONE_ACTOR = "system:clone-detection";

	private final InternalMtlsCaService mtlsCa;
	private final AgentIdentityRepository agentIdentities;
	private final NodeRepository nodes;
	private final AccessLockRepository accessLocks;
	private final LockFeedHub lockFeedHub;
	private final AgentSecurityAlerts alerts;
	private final AgentJoinProperties properties;
	private final AuditEventStore audit;
	private final TransactionalOperator tx;
	private final ObjectMapper objectMapper;

	public AgentRenewalService(InternalMtlsCaService mtlsCa, AgentIdentityRepository agentIdentities,
			NodeRepository nodes, AccessLockRepository accessLocks, LockFeedHub lockFeedHub, AgentSecurityAlerts alerts,
			AgentJoinProperties properties, AuditEventStore audit, TransactionalOperator tx,
			ObjectMapper objectMapper) {
		this.mtlsCa = mtlsCa;
		this.agentIdentities = agentIdentities;
		this.nodes = nodes;
		this.accessLocks = accessLocks;
		this.lockFeedHub = lockFeedHub;
		this.alerts = alerts;
		this.properties = properties;
		this.audit = audit;
		this.tx = tx;
		this.objectMapper = objectMapper;
	}

	public Mono<IssuedAgentIdentity> renew(UUID callerAgentId, String presentedFingerprint, byte[] csrDer,
			long currentGeneration) {
		if (callerAgentId == null) {
			return Mono.error(unauthenticated());
		}
		return agentIdentities.findById(callerAgentId).switchIfEmpty(Mono.error(unauthenticated()))
				.flatMap(identity -> renewFor(identity, presentedFingerprint, csrDer, currentGeneration));
	}

	private Mono<IssuedAgentIdentity> renewFor(AgentIdentity identity, String presentedFingerprint, byte[] csrDer,
			long currentGeneration) {
		if (!"active".equals(identity.status())) {
			return denied(identity, "inactive");
		}
		// The presented cert must be the current or previous-generation cert — a
		// superseded/stolen prior cert cannot renew. {current, prev} tolerates overlap.
		if (!fingerprintPins(identity, presentedFingerprint)) {
			return denied(identity, "fingerprint_mismatch");
		}
		return nodes.findById(identity.nodeId()).switchIfEmpty(Mono.error(unauthenticated()))
				.flatMap(node -> renewForNode(identity, node, csrDer, currentGeneration));
	}

	private Mono<IssuedAgentIdentity> renewForNode(AgentIdentity identity, Node node, byte[] csrDer,
			long currentGeneration) {
		Pkcs10Csrs.ParsedCsr csr;
		try {
			csr = Pkcs10Csrs.parseAndVerify(csrDer);
		} catch (Pkcs10Csrs.CsrException e) {
			return Mono.error(new AgentJoinException(AgentJoinException.Reason.INVALID_ARGUMENT, "invalid CSR"));
		}
		if (!node.name().equals(csr.commonName())) {
			return Mono.error(new AgentJoinException(AgentJoinException.Reason.INVALID_ARGUMENT,
					"CSR subject does not match identity"));
		}
		if (currentGeneration != identity.generation()) {
			// §8.2 clone detection: refuse + auto-lock (stale copy AND fork), no
			// auto-clear.
			return autoLock(identity.id(), identity.nodeId(), identity.generation(), currentGeneration);
		}
		long newGeneration = identity.generation() + 1;
		return mtlsCa.activeBackend().flatMap(backend -> {
			Instant now = Instant.now();
			Instant notBefore = now.minus(properties.getCertBackdate());
			Instant notAfter = now.plus(properties.getIdentityCertTtl());
			// X.509 issuance (ECDSA sign) is CPU-bound — off the reactive event loop.
			return Mono
					.fromCallable(() -> backend.issueLeaf(new LeafCertificateSpec(csr.publicKey(), node.name(),
							List.of(node.name()), List.of(AgentIdentityUri.of(identity.id())), LeafPurpose.CLIENT,
							AgentCertificates.serial(Uuids.v7()), notBefore, notAfter)))
					.subscribeOn(Schedulers.boundedElastic()).flatMap(leaf -> {
						String fingerprint = CertificateFingerprints.sha256Hex(leaf);
						// Record the OUTGOING fingerprint as prev_fingerprint so the pin
						// tolerates the renew-ahead overlap until the next renew.
						AgentIdentity renewed = new AgentIdentity(identity.id(), identity.nodeId(),
								"mtls:" + identity.id() + ":" + newGeneration, fingerprint, identity.fingerprint(),
								newGeneration, identity.joinMethod(), identity.status(), notBefore, notAfter,
								identity.statusReason(), identity.statusChangedBy(), identity.statusChangedAt(),
								identity.version(), identity.createdAt(), identity.updatedAt());
						return agentIdentities.save(renewed)
								.then(audit.record(node.name(), identity.id().toString(), "agent.renew", "success",
										null, identity.nodeId(),
										Map.of("generation", Long.toString(newGeneration), "fingerprint", fingerprint)))
								.thenReturn(AgentCertificates.toIssued(leaf, backend, identity.id(), identity.nodeId(),
										newGeneration, notBefore, notAfter))
								// A concurrent renewal lost the @Version race — for S12 that too is a
								// clone signal, so take the auto-lock path (not a silent retry).
								.onErrorResume(OptimisticLockingFailureException.class, race -> autoLock(identity.id(),
										identity.nodeId(), identity.generation(), currentGeneration));
					});
		});
	}

	/**
	 * Lock the identity + its node and alert (§8.2). Re-reads the identity fresh so
	 * it works from either entry path (an explicit mismatch or a lost @Version
	 * race). All DB writes (status flip + lock insert + audit) are one transaction;
	 * the lock is pushed AFTER commit (mirror {@code LockController}); then the
	 * renewal is refused. Never emits a value — always errors FAILED_PRECONDITION.
	 */
	private Mono<IssuedAgentIdentity> autoLock(UUID agentId, UUID nodeId, long expectedGeneration,
			long presentedGeneration) {
		Instant now = Instant.now();
		Map<String, String> detail = Map.of("expected", Long.toString(expectedGeneration), "presented",
				Long.toString(presentedGeneration));
		Mono<AccessLock> committed = tx.transactional(agentIdentities.findById(agentId).flatMap(fresh -> {
			AccessLock lock = AccessLock.create(cloneLockSelector(nodeId, agentId), "strict", null, null, CLONE_REASON,
					CLONE_ACTOR);
			Mono<AccessLock> lockCreate = accessLocks.save(lock)
					.flatMap(saved -> audit.record(CLONE_ACTOR, agentId.toString(), "agent.renew.generation_mismatch",
							"failure", null, nodeId, detail).thenReturn(saved));
			// If the other racer already locked the identity, don't re-lock/duplicate —
			// its auto-lock already created the covering lock + alert; just refuse below.
			return "active".equals(fresh.status())
					? agentIdentities.save(lockedCopy(fresh, now)).then(lockCreate)
					: Mono.empty();
		}));
		return committed.flatMap(lock -> {
			lockFeedHub.publishAdded(lock);
			return alerts.cloneDetected(agentId, nodeId, expectedGeneration, presentedGeneration);
		}).then(Mono.error(generationMismatch()));
	}

	private static AgentIdentity lockedCopy(AgentIdentity fresh, Instant now) {
		return new AgentIdentity(fresh.id(), fresh.nodeId(), fresh.mtlsIdentityRef(), fresh.fingerprint(),
				fresh.prevFingerprint(), fresh.generation(), fresh.joinMethod(), "locked", fresh.issuedAt(),
				fresh.notAfter(), CLONE_REASON, CLONE_ACTOR, now, fresh.version(), fresh.createdAt(),
				fresh.updatedAt());
	}

	/**
	 * The clone lock must reach the cloned agent as a <b>peer</b>, not only as a
	 * node. An agent's certificate carries its node NAME (dNSName SAN) and its
	 * agent id (URI SAN) — never the node UUID — so a {@code node_ids}-only
	 * selector can match the session path but cannot match an agent control
	 * channel, and the Gateway would not refuse the clone at registration or
	 * dial-back (S14). Carry both facets. {@code identities} cannot over-block: on
	 * the session path that facet is matched against the human subject identity,
	 * which is never an agent UUID.
	 */
	private ObjectNode cloneLockSelector(UUID nodeId, UUID agentId) {
		ObjectNode selector = objectMapper.createObjectNode();
		ArrayNode nodeIds = selector.putArray("node_ids");
		nodeIds.add(nodeId.toString());
		ArrayNode identities = selector.putArray("identities");
		identities.add(agentId.toString());
		return selector;
	}

	private static boolean fingerprintPins(AgentIdentity identity, String presented) {
		return presented != null
				&& (presented.equals(identity.fingerprint()) || presented.equals(identity.prevFingerprint()));
	}

	// Audit the fail-closed denial (generic to the client, specific reason
	// server-side).
	private Mono<IssuedAgentIdentity> denied(AgentIdentity identity, String reason) {
		return audit
				.record(identity.id().toString(), identity.id().toString(), "agent.renew", "denied", null,
						identity.nodeId(), Map.of("reason", reason))
				.then(Mono
						.error(new AgentJoinException(AgentJoinException.Reason.PERMISSION_DENIED, "renewal refused")));
	}

	private static AgentJoinException unauthenticated() {
		return new AgentJoinException(AgentJoinException.Reason.UNAUTHENTICATED, "agent identity unknown");
	}

	private static AgentJoinException generationMismatch() {
		return new AgentJoinException(AgentJoinException.Reason.FAILED_PRECONDITION,
				"generation mismatch (renewal refused)");
	}
}
