package io.sessionlayer.controlplane.jit;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.authz.Capabilities;
import io.sessionlayer.controlplane.authz.Selectors;
import io.sessionlayer.controlplane.data.config.JitPolicy;
import io.sessionlayer.controlplane.data.config.JitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.JitRequest;
import io.sessionlayer.controlplane.data.runtime.JitRequestRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.LockFeedHub;
import io.sessionlayer.controlplane.jit.JitApprovalChain.Level;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The JIT access-model state machine (FR-ACC-2/3/4). Drives
 * {@code runtime.jit_request} through REQUESTED → PENDING_APPROVAL →
 * {APPROVED|DENIED|EXPIRED} → ACTIVE → {EXPIRED|REVOKED}, with two independent
 * clocks — the approval window ({@code approval_deadline}) and the grant TTL
 * ({@code grant_expires_at}, started at final approval and snapshotted from the
 * policy at submit). Every transition is audited. Self-approval is impossible
 * (FR-ACC-4): an approver can never be the requester and may act at most once,
 * enforced here over the snapshotted chain so no config or re-request can
 * bypass it.
 *
 * <p>
 * A usable grant (APPROVED/ACTIVE with an unelapsed grant clock) is consumed by
 * the {@code Authorize} evaluator, which synthesizes an in-memory allow and
 * re-runs the deny-overrides engine — so a Lock still denies a JIT grant (deny
 * wins), even a zero-approval one. Revoking an APPROVED/ACTIVE grant writes a
 * short-lived strict {@code access_lock} targeting the grant's IDENTITY (not
 * the node — that would deny every user on the node) so a LIVE session tears
 * down (S10) then the lock auto-clears; the REVOKED state is what blocks
 * re-auth.
 */
@Service
public class JitLifecycleService {

	private static final Logger LOG = LoggerFactory.getLogger(JitLifecycleService.class);
	private static final String NOT_REQUESTABLE_MSG = "target is not available for JIT access";

	private final JitRequestRepository requests;
	private final JitPolicyRepository policies;
	private final NodeRepository nodes;
	private final AccessLockRepository accessLocks;
	private final LockFeedHub lockFeedHub;
	private final AuditWriter audit;
	private final JitProperties properties;
	private final TransactionalOperator tx;
	private final ObjectMapper objectMapper;

	public JitLifecycleService(JitRequestRepository requests, JitPolicyRepository policies, NodeRepository nodes,
			AccessLockRepository accessLocks, LockFeedHub lockFeedHub, AuditWriter audit, JitProperties properties,
			TransactionalOperator tx, ObjectMapper objectMapper) {
		this.requests = requests;
		this.policies = policies;
		this.nodes = nodes;
		this.accessLocks = accessLocks;
		this.lockFeedHub = lockFeedHub;
		this.audit = audit;
		this.properties = properties;
		this.tx = tx;
		this.objectMapper = objectMapper;
	}

	// ----- submit (FR-ACC-2) -----

	public Mono<JitRequest> submit(String requester, UUID targetNodeId, String principal, List<String> capabilities,
			String reason) {
		if (blank(requester) || blank(principal) || blank(reason) || targetNodeId == null) {
			return Mono.error(new JitException(JitException.Reason.INVALID,
					"requester, target node, principal and reason are required"));
		}
		// The client sees ONE generic message for both a missing node and a
		// non-requestable one (no node-existence oracle); the specific reason is kept
		// server-side in the audit note.
		return nodes.findById(targetNodeId)
				.flatMap(node -> matchingPolicy(node)
						.flatMap(policy -> create(requester, node, policy, principal, capabilities, reason))
						.switchIfEmpty(Mono.defer(() -> rejectSubmit(requester, targetNodeId, "no_policy"))))
				.switchIfEmpty(Mono.defer(() -> rejectSubmit(requester, targetNodeId, "unknown_node")));
	}

	private Mono<JitPolicy> matchingPolicy(Node node) {
		Map<String, String> labels = labelsOf(node.resolvedLabels());
		return policies.findAll().filter(policy -> matchesNode(policy, labels))
				.sort((a, b) -> a.name().compareTo(b.name())).next();
	}

	// Fail closed on a malformed policy selector (matches the S5 evaluator's
	// posture): one bad jit_policy row must not throw and 500 every submit.
	private static boolean matchesNode(JitPolicy policy, Map<String, String> labels) {
		try {
			return Selectors.labelMatches(policy.targetSelector(), labels);
		} catch (RuntimeException malformed) {
			LOG.warn("skipping jit_policy {} with an unparseable target selector: {}", policy.name(),
					malformed.getMessage());
			return false;
		}
	}

	private Mono<JitRequest> rejectSubmit(String requester, UUID targetNodeId, String note) {
		return audit.record(requester, null, "jit.requested", "denied", null, targetNodeId, detail("reason", note))
				.then(Mono.error(new JitException(JitException.Reason.NOT_REQUESTABLE, NOT_REQUESTABLE_MSG)));
	}

	private Mono<JitRequest> create(String requester, Node node, JitPolicy policy, String principal,
			List<String> requestedCaps, String reason) {
		Instant now = Instant.now();
		List<String> caps = effectiveCapabilities(requestedCaps, policy.capabilities());
		List<Level> chain = JitApprovalChain.levels(policy.approvalChain());
		Instant approvalDeadline = now.plus(properties.getApprovalWindow());
		ArrayNode noApprovals = objectMapper.createArrayNode();
		Integer maxTtl = policy.maxTtlSeconds();

		if (chain.isEmpty()) {
			// A zero-level chain still produces a grant (the grant clock starts now), but
			// it is fed through the engine at Authorize, so a Lock still denies it.
			Instant grantExpiry = now.plus(grantTtl(maxTtl));
			JitRequest approved = JitRequest.create(requester, node.id(), node.name(), null, principal, caps, reason,
					JitRequest.APPROVED, policy.id(), policy.name(), maxTtl, policy.approvalChain(), noApprovals,
					approvalDeadline, grantExpiry, now);
			return tx.transactional(requests.save(approved)
					.flatMap(saved -> auditTransition(saved, "jit.requested", "success", stateDetail(saved))
							.then(auditTransition(saved, "jit.approved", "success",
									detail("chain", "0", "grant_expires_at", grantExpiry.toString())))
							.thenReturn(saved)));
		}

		JitRequest pending = JitRequest.create(requester, node.id(), node.name(), null, principal, caps, reason,
				JitRequest.PENDING_APPROVAL, policy.id(), policy.name(), maxTtl, policy.approvalChain(), noApprovals,
				approvalDeadline, null, now);
		return tx
				.transactional(
						requests.save(pending)
								.flatMap(
										saved -> auditTransition(saved, "jit.requested", "success", stateDetail(saved))
												.then(auditTransition(saved, "jit.pending", "success",
														detail("levels", Integer.toString(chain.size()),
																"approval_deadline", approvalDeadline.toString())))
												.thenReturn(saved)));
	}

	// ----- approve / deny (FR-ACC-3/4) -----

	public Mono<JitRequest> approve(UUID requestId, String approver, List<String> approverGroups, String reason) {
		return act(requestId, approver, approverGroups, reason, true);
	}

	public Mono<JitRequest> deny(UUID requestId, String approver, List<String> approverGroups, String reason) {
		return act(requestId, approver, approverGroups, reason, false);
	}

	private Mono<JitRequest> act(UUID requestId, String approver, List<String> approverGroups, String reason,
			boolean approve) {
		if (blank(approver)) {
			return Mono.error(new JitException(JitException.Reason.INVALID, "approver is required"));
		}
		Instant now = Instant.now();
		return requests.findById(requestId)
				.switchIfEmpty(Mono.error(new JitException(JitException.Reason.NOT_FOUND, "jit request not found")))
				.flatMap(request -> {
					if (!JitRequest.PENDING_APPROVAL.equals(request.state())) {
						return auditReject(request, "not_pending", approver)
								.then(Mono.error(new JitException(JitException.Reason.NOT_PENDING,
										"jit request is not pending approval")));
					}
					// The approval window is a hard clock: an approval landing after it (before
					// the sweep) must NOT grant a fresh TTL — lazily flip to EXPIRED + audit and
					// reject, symmetric with the grant path's read-time expiry.
					if (elapsed(request.approvalDeadline(), now)) {
						return lazilyExpire(request, now).then(Mono.error(
								new JitException(JitException.Reason.NOT_PENDING, "the approval window has elapsed")));
					}
					// FR-ACC-4 hard invariant, checked BEFORE any level match: the requester can
					// never approve/deny their own request, whatever the chain config says.
					if (request.requester().equals(approver)) {
						return auditReject(request, "self_approval", approver)
								.then(Mono.error(new JitException(JitException.Reason.SELF_APPROVAL,
										"the requester cannot decide their own request")));
					}
					if (JitApprovalChain.hasActed(request.approvals(), approver)) {
						return auditReject(request, "already_acted", approver)
								.then(Mono.error(new JitException(JitException.Reason.ALREADY_ACTED,
										"this approver has already acted on this request")));
					}
					List<Level> chain = JitApprovalChain.levels(request.approvalChain());
					int level = JitApprovalChain.approvedCount(request.approvals());
					if (level >= chain.size()
							|| !JitApprovalChain.matches(chain.get(level), approver, approverGroups)) {
						return auditReject(request, "not_an_approver", approver)
								.then(Mono.error(new JitException(JitException.Reason.NOT_AN_APPROVER,
										"not an approver for the next chain level")));
					}
					return approve
							? applyApproval(request, approver, reason, chain, level, now)
							: applyDenial(request, approver, reason, level, now);
				});
	}

	private Mono<JitRequest> applyApproval(JitRequest request, String approver, String reason, List<Level> chain,
			int level, Instant now) {
		ArrayNode approvals = JitApprovalChain.append(objectMapper, request.approvals(), approver, level, "approve",
				reason, now);
		boolean complete = level + 1 >= chain.size();
		if (complete) {
			// The grant clock starts at final approval, from the SUBMIT-time snapshot of
			// the policy max_ttl (never re-read live — a mid-flight policy edit/delete
			// cannot widen or fail-open the grant), bounded by the cluster ceiling.
			Instant grantExpiry = now.plus(grantTtl(request.policyMaxTtlSeconds()));
			JitRequest approved = request.approved(approvals, grantExpiry, approver, now);
			return tx.transactional(requests.save(approved)
					.flatMap(saved -> auditTransition(saved, "jit.approved", "success", detail("approver", approver,
							"level", Integer.toString(level), "grant_expires_at", grantExpiry.toString()))
							.thenReturn(saved)));
		}
		JitRequest advanced = request.withApprovals(approvals);
		return tx
				.transactional(
						requests.save(advanced)
								.flatMap(saved -> auditTransition(saved, "jit.approve", "success",
										detail("approver", approver, "level", Integer.toString(level)))
										.thenReturn(saved)));
	}

	private Mono<JitRequest> applyDenial(JitRequest request, String approver, String reason, int level, Instant now) {
		ArrayNode approvals = JitApprovalChain.append(objectMapper, request.approvals(), approver, level, "deny",
				reason, now);
		JitRequest denied = request.denied(approvals, approver, reason, now);
		return tx
				.transactional(
						requests.save(denied)
								.flatMap(saved -> auditTransition(saved, "jit.denied", "denied",
										detail("approver", approver, "level", Integer.toString(level)))
										.thenReturn(saved)));
	}

	// ----- revoke → Lock (Part E) -----

	public Mono<JitRequest> revoke(UUID requestId, String actor, String reason) {
		Instant now = Instant.now();
		// The lock exists ONLY to tear down the LIVE session, so give it a bounded,
		// self-clearing TTL (the REVOKED state blocks re-auth) and target the grant's
		// IDENTITY only — a node facet would strict-lock EVERY user on the target node.
		int ttlSeconds = (int) Math.max(1, properties.getRevokeLockTtl().toSeconds());
		Instant expiresAt = now.plusSeconds(ttlSeconds);
		Mono<Revocation> committed = tx.transactional(requests.findById(requestId)
				.switchIfEmpty(Mono.error(new JitException(JitException.Reason.NOT_FOUND, "jit request not found")))
				.flatMap(request -> {
					if (!JitRequest.APPROVED.equals(request.state()) && !JitRequest.ACTIVE.equals(request.state())) {
						return Mono.error(new JitException(JitException.Reason.NOT_REVOCABLE,
								"only an approved or active grant can be revoked"));
					}
					JitRequest revoked = request.revoked(actor, reason, now);
					AccessLock lock = AccessLock.create(revokeSelector(request), "strict", ttlSeconds, expiresAt,
							revokeReason(request, reason), actor);
					return requests.save(revoked).then(accessLocks.save(lock))
							.flatMap(savedLock -> auditTransition(revoked, "jit.revoked", "success",
									detail("actor", actor, "lock_id", savedLock.id().toString()))
									.thenReturn(new Revocation(revoked, savedLock)));
				}));
		return committed.map(revocation -> {
			lockFeedHub.publishAdded(revocation.lock());
			return revocation.request();
		})
				// A concurrent revoke that lost the @Version race: re-read; if already REVOKED
				// return it idempotently, else it moved to a non-revocable state.
				.onErrorResume(OptimisticLockingFailureException.class,
						race -> requests.findById(requestId)
								.flatMap(fresh -> JitRequest.REVOKED.equals(fresh.state())
										? Mono.just(fresh)
										: Mono.error(new JitException(JitException.Reason.NOT_REVOCABLE,
												"only an approved or active grant can be revoked"))));
	}

	private record Revocation(JitRequest request, AccessLock lock) {
	}

	// ----- expiry (both clocks) -----

	/**
	 * Transition every overdue row to EXPIRED (approval window elapsed while
	 * REQUESTED/PENDING_APPROVAL; grant clock elapsed while APPROVED/ACTIVE) and
	 * audit each. Idempotent and per-row fault-tolerant: a lost {@code @Version}
	 * update OR any other per-row error is logged and skipped so one bad row never
	 * aborts the whole sweep. Callable by the scheduler and directly by tests.
	 * Returns how many rows this call expired.
	 */
	public Mono<Long> expireOverdue() {
		Instant now = Instant.now();
		Flux<JitRequest> overdue = Flux
				.concat(requests.findByState(JitRequest.REQUESTED), requests.findByState(JitRequest.PENDING_APPROVAL),
						requests.findByState(JitRequest.APPROVED), requests.findByState(JitRequest.ACTIVE))
				.filter(request -> isOverdue(request, now));
		return overdue.flatMap(request -> lazilyExpire(request, now).thenReturn(1L).onErrorResume(error -> {
			LOG.warn("jit expiry: could not expire {} — skipped: {}", request.id(), error.toString());
			return Mono.just(0L);
		}), 4).reduce(0L, Long::sum);
	}

	// Flip one request to EXPIRED + audit, in its own transaction. Empty (not
	// error)
	// on a lost @Version race — another writer already expired it.
	private Mono<Void> lazilyExpire(JitRequest request, Instant now) {
		return tx
				.transactional(requests.save(request.expired(now))
						.flatMap(saved -> auditTransition(saved, "jit.expired", "success",
								detail("prior_state", request.state()))))
				.onErrorResume(OptimisticLockingFailureException.class, race -> Mono.empty());
	}

	private static boolean isOverdue(JitRequest request, Instant now) {
		return switch (request.state()) {
			case JitRequest.REQUESTED, JitRequest.PENDING_APPROVAL -> elapsed(request.approvalDeadline(), now);
			case JitRequest.APPROVED, JitRequest.ACTIVE -> elapsed(request.grantExpiresAt(), now);
			default -> false;
		};
	}

	private static boolean elapsed(Instant deadline, Instant now) {
		return deadline != null && !deadline.isAfter(now);
	}

	// ----- Authorize consumption (Part E) -----

	/**
	 * The usable JIT grant for {@code requester} on {@code nodeId} as
	 * {@code principal}, if any: APPROVED/ACTIVE, matching target, grant clock not
	 * elapsed. Deterministic — the earliest-expiring usable grant. Never serves an
	 * overdue grant (lazy expiry on read); the scheduler/{@link #expireOverdue()}
	 * does the durable state flip.
	 */
	public Mono<JitRequest> findUsableGrant(String requester, UUID nodeId, String principal, Instant now) {
		if (blank(requester) || nodeId == null || blank(principal)) {
			return Mono.empty();
		}
		return requests.findByRequester(requester)
				.filter(request -> request.usableAt(now) && nodeId.equals(request.targetNodeId())
						&& principal.equals(request.principal()))
				.sort(Comparator.comparing(JitRequest::grantExpiresAt)).next();
	}

	/** APPROVED → ACTIVE on first consumption at Authorize (idempotent). */
	public Mono<JitRequest> markActive(JitRequest request) {
		if (JitRequest.ACTIVE.equals(request.state())) {
			return Mono.just(request);
		}
		JitRequest active = request.activated();
		return tx
				.transactional(requests.save(active)
						.flatMap(saved -> auditTransition(saved, "jit.activated", "success",
								detail("grant_expires_at", String.valueOf(saved.grantExpiresAt()))).thenReturn(saved)))
				// A lost race (another connect activated it first) is benign — it is ACTIVE.
				.onErrorResume(OptimisticLockingFailureException.class, race -> Mono.just(active));
	}

	// ----- helpers -----

	// Grant clock = min(snapshot max_ttl, cluster ceiling). A null/non-positive
	// snapshot (only a legacy row) falls to the ceiling; a real snapshot never
	// does.
	private Duration grantTtl(Integer snapshotMaxTtl) {
		long ceiling = properties.getMaxGrantTtl().toSeconds();
		long base = (snapshotMaxTtl == null || snapshotMaxTtl <= 0) ? ceiling : snapshotMaxTtl;
		return Duration.ofSeconds(Math.min(Math.max(1, base), ceiling));
	}

	private static List<String> effectiveCapabilities(List<String> requested, List<String> policyCaps) {
		List<String> allowed = policyCaps == null || policyCaps.isEmpty()
				? List.copyOf(Capabilities.DEFAULT)
				: policyCaps;
		if (requested == null || requested.isEmpty()) {
			return List.copyOf(allowed);
		}
		// Deny-only: a request can only narrow the policy's capability set.
		return requested.stream().filter(allowed::contains).distinct().toList();
	}

	private ObjectNode revokeSelector(JitRequest request) {
		ObjectNode selector = objectMapper.createObjectNode();
		selector.putArray("identities").add(request.requester());
		return selector;
	}

	private static String revokeReason(JitRequest request, String reason) {
		return blank(reason) ? "jit revoked" : "jit revoked: " + reason;
	}

	private Mono<Void> auditReject(JitRequest request, String reason, String approver) {
		return auditTransition(request, "jit.approve", "denied", detail("reason", reason, "approver", approver));
	}

	private Mono<Void> auditTransition(JitRequest request, String action, String outcome, Map<String, String> detail) {
		Map<String, String> full = new HashMap<>(detail);
		full.put("state", request.state());
		full.put("jit_request_id", request.id().toString());
		return audit.record(request.requester(), request.principal(), action, outcome, null, request.targetNodeId(),
				full);
	}

	private static Map<String, String> stateDetail(JitRequest request) {
		return detail("principal", request.principal(), "policy", nullSafe(request.jitPolicyName()));
	}

	private static Map<String, String> detail(String... kv) {
		Map<String, String> map = new HashMap<>();
		for (int i = 0; i + 1 < kv.length; i += 2) {
			map.put(kv[i], kv[i + 1]);
		}
		return map;
	}

	private static Map<String, String> labelsOf(JsonNode resolvedLabels) {
		Map<String, String> labels = new HashMap<>();
		if (resolvedLabels != null && resolvedLabels.isObject()) {
			for (var entry : resolvedLabels.properties()) {
				labels.put(entry.getKey(), entry.getValue().asString());
			}
		}
		return labels;
	}

	private static boolean blank(String value) {
		return value == null || value.isBlank();
	}

	private static String nullSafe(String value) {
		return value == null ? "" : value;
	}
}
