package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditRecord;
import io.sessionlayer.controlplane.breakglass.BreakglassProperties;
import io.sessionlayer.controlplane.breakglass.BreakglassTokenService;
import io.sessionlayer.controlplane.ca.CaRotationService;
import io.sessionlayer.controlplane.data.config.BreakglassPolicy;
import io.sessionlayer.controlplane.data.config.BreakglassPolicyRepository;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.config.PolicyEpochRepository;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivationRepository;
import io.sessionlayer.controlplane.data.runtime.BreakglassToken;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.JitRequest;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeHostKeyRepository;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.PresenceRepository;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.gateway.SessionSigningTokenService;
import io.sessionlayer.controlplane.ha.HaProperties;
import io.sessionlayer.controlplane.jit.JitLifecycleService;
import io.sessionlayer.controlplane.recording.RecordingTokenService;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * Orchestrates the connect-time decision (Part B, FR-CHAN-1) across the three
 * access models (§7, S13). It resolves the node's labels, evaluates the
 * standing data-plane RBAC set with the {@link PolicyEngine} (deny-overrides),
 * and:
 *
 * <ul>
 * <li><b>STANDING</b> — a standing allow proceeds unchanged.</li>
 * <li><b>JIT</b> — a standing default-deny ({@code NO_MATCHING_ALLOW} only,
 * never a Lock or explicit deny) may be satisfied by an ACTIVE/APPROVED JIT
 * grant: the grant is synthesized as an in-memory allow and the engine is
 * <b>re-run</b>, so a Lock or explicit deny still wins (deny wins). A usable
 * grant flips APPROVED → ACTIVE.</li>
 * <li><b>BREAK-GLASS</b> — a present {@code breakglass_token} is consumed
 * atomically; on a valid token the {@code breakglass_activation} +
 * high-priority alert are raised UNCONDITIONALLY (before the decision), then
 * the allow is evaluated SUBJECT TO the top-tier Lock (a locked target still
 * denies; the activation stands). Break-glass bypasses the standing dp_rule
 * deny but never the Lock.</li>
 * </ul>
 *
 * <p>
 * On allow it produces a signed decision context (carrying the access model),
 * writes the {@code ssh_session} decision snapshot, and mints the single-use
 * {@code session_signing_token} + {@code recording_token} bound to the
 * AUTHENTICATED caller gateway. On deny/Lock (and any datastore/evaluation
 * error) it mints nothing and records the specific reason to the decision log
 * while the caller sees only a generic deny (FR-AUTHZ-5, §8.4).
 */
@Service
public class ConnectAuthorizationService {

	private static final Logger LOG = LoggerFactory.getLogger(ConnectAuthorizationService.class);
	private static final String DECISION_ACTION = "authz.decision";
	private static final String MODEL_STANDING = "standing";
	private static final String MODEL_JIT = "jit";
	private static final String MODEL_BREAKGLASS = "breakglass";

	private final NodeRepository nodes;
	private final NodeHostKeyRepository hostKeys;
	private final CaRotationService caRotation;
	private final DpRuleRepository dpRules;
	private final AccessLockRepository accessLocks;
	private final PolicyEpochRepository policyEpochs;
	private final GatewayIdentityRepository gatewayIdentities;
	private final SshSessionRepository sshSessions;
	private final SessionLeaseRepository sessionLeases;
	private final SessionLimitPolicyRepository sessionLimitPolicies;
	private final OperatorSettingsRepository operatorSettings;
	private final PolicyEngine engine;
	private final DecisionContextSigner signer;
	private final SessionSigningTokenService tokens;
	private final RecordingTokenService recordingTokens;
	private final JitLifecycleService jit;
	private final BreakglassTokenService breakglassTokens;
	private final BreakglassActivationRepository breakglassActivations;
	private final BreakglassPolicyRepository breakglassPolicies;
	private final BreakglassProperties breakglassProperties;
	private final AuditEventStore audit;
	private final AuthzProperties properties;
	private final PresenceRepository presence;
	private final HaProperties haProperties;
	private final ObjectMapper objectMapper;
	private final TransactionalOperator tx;
	private final DatabaseClient db;

	public ConnectAuthorizationService(NodeRepository nodes, NodeHostKeyRepository hostKeys,
			CaRotationService caRotation, DpRuleRepository dpRules, AccessLockRepository accessLocks,
			PolicyEpochRepository policyEpochs, GatewayIdentityRepository gatewayIdentities,
			SshSessionRepository sshSessions, SessionLeaseRepository sessionLeases,
			SessionLimitPolicyRepository sessionLimitPolicies, OperatorSettingsRepository operatorSettings,
			PolicyEngine engine, DecisionContextSigner signer, SessionSigningTokenService tokens,
			RecordingTokenService recordingTokens, JitLifecycleService jit, BreakglassTokenService breakglassTokens,
			BreakglassActivationRepository breakglassActivations, BreakglassPolicyRepository breakglassPolicies,
			BreakglassProperties breakglassProperties, AuditEventStore audit, AuthzProperties properties,
			PresenceRepository presence, HaProperties haProperties, ObjectMapper objectMapper, TransactionalOperator tx,
			DatabaseClient db) {
		this.nodes = nodes;
		this.hostKeys = hostKeys;
		this.caRotation = caRotation;
		this.dpRules = dpRules;
		this.accessLocks = accessLocks;
		this.policyEpochs = policyEpochs;
		this.gatewayIdentities = gatewayIdentities;
		this.sshSessions = sshSessions;
		this.sessionLeases = sessionLeases;
		this.sessionLimitPolicies = sessionLimitPolicies;
		this.operatorSettings = operatorSettings;
		this.engine = engine;
		this.signer = signer;
		this.tokens = tokens;
		this.recordingTokens = recordingTokens;
		this.jit = jit;
		this.breakglassTokens = breakglassTokens;
		this.breakglassActivations = breakglassActivations;
		this.breakglassPolicies = breakglassPolicies;
		this.breakglassProperties = breakglassProperties;
		this.audit = audit;
		this.properties = properties;
		this.presence = presence;
		this.haProperties = haProperties;
		this.objectMapper = objectMapper;
		this.tx = tx;
		this.db = db;
	}

	public Mono<ConnectDecision> authorize(UUID callerGatewayId, String presentedFingerprint, String identity,
			List<String> groups, UUID nodeId, String nodeName, String requestedPrincipal, String sourceIp,
			UUID sessionId, String breakglassToken) {
		boolean hasName = !isBlank(nodeName);
		// The connect decision requires a concrete authenticated caller, target,
		// session, resolved identity, and requested login — the target is resolvable by
		// NAME or by id. A blank one of these is meaningless and fails closed (never
		// allow/mint on a subject-less probe).
		if (callerGatewayId == null || sessionId == null || isBlank(identity) || isBlank(requestedPrincipal)
				|| (!hasName && nodeId == null)) {
			return denyMissingInput(callerGatewayId, identity, nodeId, sourceIp);
		}
		// §2.6/§11 (FR-ADDR-1): name resolution is server-side AUTHORITATIVE — when a
		// name is present the CP resolves it via findByName and IGNORES any
		// client-asserted node_id, so a client can never smuggle an id past the
		// resolved
		// name. An unknown name yields the SAME generic node_unknown deny as any other
		// no-match (no existence disclosure, §7.1).
		Mono<Node> resolved = hasName ? nodes.findByName(nodeName) : nodes.findById(nodeId);
		// FR-BOOT-3 / §8.4 / FR-LOCK-2: the caller Gateway is a first-class lockable
		// principal, so EVERY connect decision is gated on the same active-status +
		// fingerprint pin the sign path enforces (requireActiveGateway), BEFORE any
		// RBAC
		// eval, break-glass/JIT consumption, or state write. A locked or
		// superseded-cert Gateway is refused on Authorize too (else its still-valid
		// cert
		// stays an RBAC oracle and can consume break-glass tokens / flip JIT grants).
		return requireActiveGateway(callerGatewayId, presentedFingerprint)
				.flatMap(
						gw -> resolved
								.flatMap(node -> decide(callerGatewayId, identity, groups, node, requestedPrincipal,
										sourceIp, sessionId, breakglassToken))
								.switchIfEmpty(auditDeny(callerGatewayId, identity, nodeId, sourceIp,
										DataPlaneDecision.deny(DataPlaneDecision.Reason.NO_MATCHING_ALLOW, null, null),
										"node_unknown", null, null).thenReturn(ConnectDecision.denied())))
				.switchIfEmpty(auditDeny(callerGatewayId, identity, nodeId, sourceIp,
						DataPlaneDecision.deny(DataPlaneDecision.Reason.NO_MATCHING_ALLOW, null, null),
						"gateway_not_authorized", null, null).thenReturn(ConnectDecision.denied()))
				// Any datastore/unexpected failure denies (fail closed, §8.4) — never leaks.
				.onErrorResume(failure -> {
					LOG.warn("connect authorization failed closed: {}", failure.toString());
					return auditError(callerGatewayId, identity, nodeId, sourceIp).thenReturn(ConnectDecision.denied());
				});
	}

	// FR-BOOT-3 / §8.4: the caller Gateway must be an ACTIVE identity whose
	// presented
	// client-cert fingerprint pins to its current or previous fingerprint (a locked
	// or
	// superseded/stolen cert is refused). The same gate the sign path enforces
	// (SessionCertificateService.requireAuthorizedGateway); empty ⇒ generic deny.
	private Mono<GatewayIdentity> requireActiveGateway(UUID callerGatewayId, String presentedFingerprint) {
		if (callerGatewayId == null || presentedFingerprint == null) {
			return Mono.empty();
		}
		return gatewayIdentities.findById(callerGatewayId).flatMap(gw -> {
			boolean active = "active".equals(gw.status());
			boolean pinned = presentedFingerprint.equals(gw.fingerprint())
					|| presentedFingerprint.equals(gw.prevFingerprint());
			return active && pinned ? Mono.just(gw) : Mono.<GatewayIdentity>empty();
		});
	}

	private Mono<ConnectDecision> decide(UUID callerGatewayId, String identity, List<String> groups, Node node,
			String requestedPrincipal, String sourceIp, UUID sessionId, String breakglassToken) {
		// Part D (FR-NODE-3): only an ACTIVE node is a valid target. A pending /
		// quarantined / removed node is denied with the SAME generic deny as an unknown
		// node (non-disclosure, §7.1); the specific status is recorded server-side.
		// This
		// gate precedes the break-glass path too — a non-active node is unreachable
		// even
		// via break-glass (belt; a quarantine Lock is the suspenders).
		if (!"active".equals(node.status())) {
			return auditDeny(callerGatewayId, identity, node.id(), sourceIp,
					DataPlaneDecision.deny(DataPlaneDecision.Reason.NO_MATCHING_ALLOW, null, null),
					"node_" + node.status(), null, null).thenReturn(ConnectDecision.denied());
		}
		Mono<Long> epochMono = policyEpochs.findSingleton().map(e -> e.epoch()).defaultIfEmpty(0L);
		Mono<String> gwNameMono = gatewayIdentities.findById(callerGatewayId).map(g -> g.name())
				.defaultIfEmpty("unknown");

		// Read grants first, THEN locks, so the lock set is observed at a snapshot no
		// earlier than the grant set (§8.4: a concurrently-added deny/lock is never
		// missed while an allow from the same edit is honored — deny stays dominant).
		return dpRules.findAll().collectList().flatMap(grants -> accessLocks.findAll().collectList()
				.flatMap(locks -> Mono.zip(epochMono, gwNameMono).flatMap(meta -> {
					long epoch = meta.getT1();
					String gatewayName = meta.getT2();
					Instant now = Instant.now();
					AuthorizationRequest request = new AuthorizationRequest(identity, groups, node.id(),
							labelsOf(node.resolvedLabels()), sourceIp, requestedPrincipal);

					// The break-glass path is a distinct, always-available authentication path
					// (I3): a present token means the user authenticated via FIDO2/offline-code,
					// so honour break-glass semantics regardless of standing rules.
					if (!isBlank(breakglassToken)) {
						return breakglass(callerGatewayId, node, gatewayName, request, sessionId, breakglassToken,
								locks, epoch, now);
					}

					DataPlaneDecision decision = engine.evaluate(request, grants, locks, now);
					if (decision.allowed()) {
						return emitAllow(callerGatewayId, node, gatewayName, request, sessionId,
								decision.sortedLogins(), decision.sortedCapabilities(), decision.matchedRuleId(),
								decision.matchedRuleName(), MODEL_STANDING, null, null, decision.grantTtlSeconds(),
								epoch, now);
					}
					// JIT elevates ONLY a default-deny (no standing allow matched). A Lock or an
					// explicit deny in the first pass is terminal — JIT never overrides it.
					if (decision.reason() == DataPlaneDecision.Reason.NO_MATCHING_ALLOW) {
						return tryJit(callerGatewayId, node, gatewayName, request, sessionId, grants, locks, epoch,
								now);
					}
					return auditDeny(callerGatewayId, request.identity(), node.id(), sourceIp, decision, null,
							MODEL_STANDING, null).thenReturn(ConnectDecision.denied());
				})));
	}

	// ----- JIT two-pass (Part E) -----

	private Mono<ConnectDecision> tryJit(UUID callerGatewayId, Node node, String gatewayName,
			AuthorizationRequest request, UUID sessionId, Collection<DpRule> grants, Collection<AccessLock> locks,
			long epoch, Instant now) {
		return jit.findUsableGrant(request.identity(), node.id(), request.requestedPrincipal(), now).flatMap(grant -> {
			// Synthesize the JIT allow in-memory and RE-RUN the engine: the lock is then
			// re-evaluated with the JIT-granted login present, so a Lock targeting that
			// login/principal now denies (deny wins). The synthetic rule is NEVER
			// persisted.
			List<DpRule> augmented = new ArrayList<>(grants);
			augmented.add(syntheticJitRule(grant, request.identity(), now));
			DataPlaneDecision decision = engine.evaluate(request, augmented, locks, now);
			if (!decision.allowed()) {
				return auditDeny(callerGatewayId, request.identity(), node.id(), request.sourceIp(), decision, "jit",
						MODEL_JIT, grant.id()).thenReturn(ConnectDecision.denied());
			}
			// The grant is usable: flip APPROVED → ACTIVE (audited), then emit the allow.
			return jit.markActive(grant)
					.then(emitAllow(callerGatewayId, node, gatewayName, request, sessionId, decision.sortedLogins(),
							decision.sortedCapabilities(), null, "jit:" + nullSafe(grant.jitPolicyName()), MODEL_JIT,
							grant.id(), null, remainingSeconds(grant.grantExpiresAt(), now), epoch, now));
		}).switchIfEmpty(auditDeny(callerGatewayId, request.identity(), node.id(), request.sourceIp(),
				DataPlaneDecision.deny(DataPlaneDecision.Reason.NO_MATCHING_ALLOW, null, null), "no_jit_grant",
				MODEL_JIT, null).thenReturn(ConnectDecision.denied()));
	}

	private DpRule syntheticJitRule(JitRequest grant, String identity, Instant now) {
		ObjectNode identitySelector = objectMapper.createObjectNode();
		ArrayNode identities = identitySelector.putArray("identities");
		identities.add(identity);
		int ttl = remainingSeconds(grant.grantExpiresAt(), now);
		// nodeLabelSelector null → matches this (fixed) node; sourceIpCondition null →
		// no
		// source restriction; origin "jit" is in-memory only (the DB origin CHECK never
		// sees it). Principals = the approved JIT login; capabilities = the approved
		// set.
		return DpRule.create("jit:" + nullSafe(grant.jitPolicyName()), identitySelector, null, null,
				List.of(grant.principal()), ttl, grant.capabilities() == null ? List.of() : grant.capabilities(),
				"allow", "jit");
	}

	// ----- break-glass (Part C/E) -----

	private Mono<ConnectDecision> breakglass(UUID callerGatewayId, Node node, String gatewayName,
			AuthorizationRequest request, UUID sessionId, String breakglassToken, Collection<AccessLock> locks,
			long epoch, Instant now) {
		return breakglassTokens
				.consume(breakglassToken, callerGatewayId, request.identity(), node.id(), request.sourceIp())
				.flatMap(token -> onValidBreakglass(callerGatewayId, node, gatewayName, request, sessionId, token,
						locks, epoch, now))
				// An invalid/replayed/cross-gateway token is not a genuine break-glass event:
				// no activation, no alert — just a generic fail-closed deny (§7.1).
				.switchIfEmpty(auditDeny(callerGatewayId, request.identity(), node.id(), request.sourceIp(),
						DataPlaneDecision.deny(DataPlaneDecision.Reason.EVALUATION_ERROR, null, null),
						"breakglass_token_invalid", MODEL_BREAKGLASS, null).thenReturn(ConnectDecision.denied()));
	}

	private Mono<ConnectDecision> onValidBreakglass(UUID callerGatewayId, Node node, String gatewayName,
			AuthorizationRequest request, UUID sessionId, BreakglassToken token, Collection<AccessLock> locks,
			long epoch, Instant now) {
		// A valid token is a genuine break-glass event: create the activation + raise
		// the
		// high-priority alert UNCONDITIONALLY, BEFORE the allow/deny decision, so a
		// locked
		// target still leaves a durable, reviewable record (FR-ACC-6, FR-AUD-7).
		return firstBreakglassPolicy().flatMap(policyOpt -> {
			BreakglassPolicy policy = policyOpt.orElse(null);
			BreakglassActivation activation = BreakglassActivation.activate(request.identity(),
					request.requestedPrincipal(), "break-glass", "audit:breakglass.activated",
					policy == null ? null : policy.id(), policy == null ? null : policy.name(), request.sourceIp(),
					node.id(), "breakglass_token:" + token.id(), now);
			Mono<BreakglassActivation> persisted = tx.transactional(breakglassActivations.save(activation)
					.flatMap(saved -> audit.record(AuditRecord
							.builder(request.identity(), request.requestedPrincipal(), "breakglass.activation",
									"success")
							.session(sessionId).node(node.id()).detail(activationDetail(saved))
							.sourceIp(auditableIp(request.sourceIp())).accessModel(MODEL_BREAKGLASS)
							.nodeLabels(labelsOf(node.resolvedLabels())).correlationId(saved.id()).build())
							.thenReturn(saved)));
			// The high-priority alert already fired at authentication (ResolveBreakglass*),
			// so this path does NOT re-alert; the persisted activation is the durable,
			// mandatory-review compensating control.
			return persisted.flatMap(saved -> decideBreakglass(callerGatewayId, node, gatewayName, request, sessionId,
					token, saved, locks, epoch, now));
		});
	}

	private Mono<ConnectDecision> decideBreakglass(UUID callerGatewayId, Node node, String gatewayName,
			AuthorizationRequest request, UUID sessionId, BreakglassToken token, BreakglassActivation activation,
			Collection<AccessLock> locks, long epoch, Instant now) {
		String principal = request.requestedPrincipal();
		boolean principalAllowed = token.allowedPrincipals() != null && token.allowedPrincipals().contains(principal);
		AccessLock lock = firstMatchingLock(request, Set.of(principal), locks, now);
		if (!principalAllowed || lock != null) {
			// A locked target refuses break-glass (deny wins) and a login outside the
			// credential's scope is refused — but the activation + alert already STAND.
			DataPlaneDecision.Reason reason = lock != null
					? DataPlaneDecision.Reason.LOCKED
					: DataPlaneDecision.Reason.PRINCIPAL_NOT_ALLOWED;
			return auditDeny(callerGatewayId, request.identity(), node.id(), request.sourceIp(),
					DataPlaneDecision.deny(reason, lock == null ? null : lock.id(), lock == null ? null : "lock"),
					"breakglass", MODEL_BREAKGLASS, activation.id()).thenReturn(ConnectDecision.denied());
		}
		int grantTtlSeconds = (int) Math.min(breakglassProperties.getGrantTtl().toSeconds(), Integer.MAX_VALUE);
		return emitAllow(callerGatewayId, node, gatewayName, request, sessionId, List.of(principal),
				Capabilities.DEFAULT.stream().sorted().toList(), null, "breakglass", MODEL_BREAKGLASS, null,
				activation.id(), grantTtlSeconds, epoch, now);
	}

	private Mono<java.util.Optional<BreakglassPolicy>> firstBreakglassPolicy() {
		return breakglassPolicies.findAll().sort((a, b) -> a.name().compareTo(b.name())).next()
				.map(java.util.Optional::of).defaultIfEmpty(java.util.Optional.empty());
	}

	// ----- allow emission (shared across models) -----

	private Mono<ConnectDecision> emitAllow(UUID callerGatewayId, Node node, String gatewayName,
			AuthorizationRequest request, UUID sessionId, List<String> logins, List<String> capabilities,
			UUID matchedRuleId, String matchedRuleName, String accessModel, UUID jitRequestId,
			UUID breakglassActivationId, int grantTtlSeconds, long epoch, Instant now) {
		String identity = request.identity();
		String requestedPrincipal = request.requestedPrincipal();
		String sourceIp = request.sourceIp();
		int ttlSeconds = effectiveGrantTtl(grantTtlSeconds);
		Instant grantExpiry = now.plusSeconds(ttlSeconds);
		// identity/groups/node-labels are signed into the context so the Gateway
		// matches
		// identity/group/label locks against trusted data (S10); the access model is
		// signed too, so the Gateway forces strict recording for break-glass and picks
		// the per-model mid-session-expiry behaviour (FR-ACC-8).
		List<String> identityGroups = request.groups() == null ? List.of() : List.copyOf(request.groups());
		List<String> nodeLabels = sortedLabelStrings(node.resolvedLabels());
		DecisionContext context = new DecisionContext(node.id(), node.name(), logins, capabilities, requestedPrincipal,
				grantExpiry, epoch, properties.getDecisionTtl(), callerGatewayId, sessionId, sourceIp, now, identity,
				identityGroups, nodeLabels, accessModel);

		return Mono.zip(signer.sign(context), resolveNodeConnection(node)).flatMap(signedAndConn -> {
			SignedDecisionContext signed = signedAndConn.getT1();
			NodeConnectionInfo nodeConnection = signedAndConn.getT2();
			SshSession session = new SshSession(sessionId, identity, node.id(), node.name(), requestedPrincipal,
					callerGatewayId, gatewayName, accessModel, capabilities, matchedRuleId, matchedRuleName,
					jitRequestId, breakglassActivationId, epoch, grantExpiry, now, null, null, null, null, null);
			Map<String, String> detail = new HashMap<>();
			detail.put("matched_rule", nullSafe(matchedRuleName));
			detail.put("principal", requestedPrincipal);
			detail.put("access_model", accessModel);
			detail.put("policy_epoch", Long.toString(epoch));
			// FR-AUD-8/9: the connect decision is the origin of the SSH audit chain — stamp
			// every searchable dimension (source IP, access model, capabilities, node-label
			// snapshot) and the correlation key so approve → connect → run → replay all
			// join by one correlation_id.
			AuditRecord auditRecord = AuditRecord
					.builder(callerGatewayId.toString(), identity, DECISION_ACTION, "success").session(sessionId)
					.node(node.id()).detail(detail).sourceIp(auditableIp(sourceIp)).accessModel(accessModel)
					.capabilities(capabilities).nodeLabels(labelsOf(node.resolvedLabels()))
					.correlationId(session.correlationId()).build();
			// ssh_session snapshot + the two single-use tokens + the allow audit are one
			// transaction: a failure rolls all back, so a token is never minted without its
			// session row (Design §12/§15). Audit last (it serializes on the chain lock).
			ConnectDecision.TraceInfo trace = new ConnectDecision.TraceInfo(accessModel, node.id(),
					session.correlationId());
			// FR-SESS-3: a STANDING/JIT session takes a concurrency lease; the lease is
			// saved AFTER the session row (its session_id FKs ssh_session) and inside the
			// same tx, so acquire is atomic with the mint. Break-glass takes no lease.
			boolean leased = !MODEL_BREAKGLASS.equals(accessModel);
			Mono<Void> acquireLease = leased
					? sessionLeases.save(SessionLease.acquire(identity, sessionId, gatewayName, now, grantExpiry))
							.then()
					: Mono.empty();
			Mono<ConnectDecision> mint = sshSessions.save(session).then(acquireLease)
					.then(tokens.mint(callerGatewayId, sessionId, node.id(), requestedPrincipal, capabilities,
							sourceIp))
					.flatMap(sessionToken -> recordingTokens
							.mint(callerGatewayId, sessionId, node.id(), requestedPrincipal, sourceIp)
							.flatMap(recordingToken -> audit.record(auditRecord).thenReturn(ConnectDecision
									.allow(signed, sessionToken, recordingToken, nodeConnection, trace))));
			// Gate on the cap BEFORE minting (count the live leases; a breach denies and
			// mints nothing — deny wins). The check runs inside the allow tx.
			return tx.transactional(enforceConcurrencyLimit(callerGatewayId, request, node, accessModel, now, mint));
		});
	}

	// FR-SESS-3: the per-identity concurrency primitive is runtime.session_lease
	// (one
	// live lease per session; count of unreleased+unexpired leases = current
	// concurrency, fleet-wide over the shared datastore). On a STANDING/JIT allow
	// with
	// a finite cap, we take a per-identity Postgres advisory xact lock BEFORE
	// counting,
	// so count-then-acquire is atomic per identity and the cap is HARD (exact) — a
	// concurrent burst from a shared/stolen credential can never overshoot it. The
	// lock
	// contends ONLY between same-identity connects (hashtext(identity)); different
	// identities never block each other, and it auto-releases at commit/rollback.
	// An
	// over-cap count mints nothing and denies (deny wins). Break-glass is EXEMPT —
	// it
	// neither counts nor consumes a lease nor takes the lock, so emergency access
	// is
	// never throttled by the cap nor eats into a user's normal budget (it is gated
	// instead by single-use token issuance + Lock supremacy + a mandatory-review
	// activation). Unlimited identities skip the lock entirely (no needless
	// serialization).
	private Mono<ConnectDecision> enforceConcurrencyLimit(UUID callerGatewayId, AuthorizationRequest request, Node node,
			String accessModel, Instant now, Mono<ConnectDecision> mint) {
		if (MODEL_BREAKGLASS.equals(accessModel)) {
			return mint;
		}
		return resolveConcurrencyLimit(request.identity(), request.groups()).flatMap(limit -> limit <= 0
				? mint
				: lockIdentity(request.identity()).then(sessionLeases.countLiveByIdentity(request.identity(), now))
						.flatMap(active -> active >= limit
								? denyConcurrencyLimit(callerGatewayId, request, node.id(), accessModel, active, limit)
								: mint))
				.switchIfEmpty(mint);
	}

	// Serialize concurrent Authorizes for one identity within their allow
	// transactions
	// (Postgres xact advisory lock, same connection as the tx; auto-released at
	// commit/rollback). Consistent lock order everywhere: per-identity BEFORE the
	// audit
	// chain lock, so it cannot deadlock with the audit-append lock.
	private Mono<Void> lockIdentity(String identity) {
		return db.sql("SELECT pg_advisory_xact_lock(hashtext(:identity))").bind("identity", identity).fetch()
				.rowsUpdated().then();
	}

	// Resolve the identity's concurrent-session cap (FR-SESS-3): a matching
	// config.session_limit_policy override wins (most-restrictive of any that match
	// by
	// identity/group selector), else the operator_settings cluster default, else
	// empty
	// ⇒ no limit (unlimited). NULL/≤0 at any level means no enforcement.
	private Mono<Integer> resolveConcurrencyLimit(String identity, List<String> groups) {
		List<String> safeGroups = groups == null ? List.of() : groups;
		return sessionLimitPolicies.findAll()
				.filter(policy -> policy.maxConcurrentSessions() != null
						&& Selectors.identityMatches(policy.identitySelector(), identity, safeGroups))
				.map(policy -> policy.maxConcurrentSessions()).reduce(Math::min)
				.switchIfEmpty(operatorSettings.findSingleton()
						.flatMap(settings -> Mono.justOrEmpty(settings.defaultMaxConcurrentSessions())));
	}

	// Mint nothing; record the specific reason server-side (the caller sees the
	// same
	// generic deny, §8.4) with the observed count vs the limit for the operator.
	private Mono<ConnectDecision> denyConcurrencyLimit(UUID callerGatewayId, AuthorizationRequest request, UUID nodeId,
			String accessModel, long active, int limit) {
		Map<String, String> detail = new HashMap<>();
		detail.put("reason", "CONCURRENT_SESSION_LIMIT");
		detail.put("note", "concurrent_session_limit");
		detail.put("active_sessions", Long.toString(active));
		detail.put("limit", Integer.toString(limit));
		if (request.sourceIp() != null) {
			detail.put("source_ip", request.sourceIp());
		}
		return bestEffortAudit(
				AuditRecord.builder(actor(callerGatewayId), request.identity(), DECISION_ACTION, "denied").node(nodeId)
						.detail(detail).sourceIp(auditableIp(request.sourceIp())).accessModel(accessModel).build())
				.thenReturn(ConnectDecision.denied());
	}

	private static AccessLock firstMatchingLock(AuthorizationRequest request, Set<String> allowedLogins,
			Collection<AccessLock> locks, Instant now) {
		LockMatching.LockSubject subject = new LockMatching.LockSubject(request.identity(),
				request.nodeId() == null ? null : request.nodeId().toString(), request.nodeLabels(),
				Set.copyOf(allowedLogins), request.requestedPrincipal(), Set.copyOf(request.groups()));
		return locks.stream().filter(lock -> lock.expiresAt() == null || lock.expiresAt().isAfter(now))
				.filter(lock -> LockMatching.matches(lock.targetSelector(), subject))
				.min(java.util.Comparator.comparing(AccessLock::id)).orElse(null);
	}

	private static int remainingSeconds(Instant grantExpiresAt, Instant now) {
		if (grantExpiresAt == null) {
			return 0;
		}
		long remaining = Duration.between(now, grantExpiresAt).toSeconds();
		return (int) Math.max(1, Math.min(remaining, Integer.MAX_VALUE));
	}

	private static Map<String, String> activationDetail(BreakglassActivation activation) {
		Map<String, String> detail = new HashMap<>();
		detail.put("activation_id", activation.id().toString());
		detail.put("principal", activation.principal());
		if (activation.credentialRef() != null) {
			detail.put("credential_ref", activation.credentialRef());
		}
		return detail;
	}

	// The node's connectivity + host-identity answer from inventory (Design §9;
	// FR-CONN-1/2/5). Reuses the already-loaded node and adds only the
	// node_host_key read (plus the trusted host-CA set when a row anchors to it) —
	// public material only, never a private key (§9.3).
	private Mono<NodeConnectionInfo> resolveNodeConnection(Node node) {
		NodeConnectionInfo.ConnectorModel model = NodeConnectionInfo.ConnectorModel.fromInventory(node.connectorKind());
		String dial = dialAddress(node);
		return hostVerification(node, model, dial).flatMap(info -> attachFreshOwner(node, info));
	}

	private Mono<NodeConnectionInfo> hostVerification(Node node, NodeConnectionInfo.ConnectorModel model, String dial) {
		return hostKeys.findByNodeId(node.id()).collectList().flatMap(rows -> {
			List<byte[]> pinned = rows.stream().filter(row -> "pinned_key".equals(row.source()))
					.map(row -> wireBlob(row.publicKey())).filter(Objects::nonNull).toList();
			// The node's enrollment host cert(s): russh negotiates only the plain host key
			// at KEX (never the live cert), so the CP hands over the stored cert to verify.
			List<byte[]> hostCerts = rows.stream().filter(row -> "host_ca".equals(row.source()))
					.map(row -> wireBlob(row.hostCertRef())).filter(Objects::nonNull).toList();
			if (hostCerts.isEmpty()) {
				return Mono.just(nodeConnection(node, model, dial, List.of(), List.of(), pinned, List.of()));
			}
			return caRotation.trustedCaKeys("host").map(caLines -> {
				List<byte[]> caKeys = caLines.stream().map(ConnectAuthorizationService::wireBlob)
						.filter(Objects::nonNull).toList();
				// Advertise the host-CA path only as a complete triple — trusted CA key(s) to
				// check the signature, the cert, and the expected principal. Missing any leg
				// the Gateway can't verify (no TOFU), so emit none and let pinned / the
				// empty-warn handle it (upholds the proto invariant: host_certificates
				// non-empty whenever host_ca_keys is set).
				if (caKeys.isEmpty()) {
					return nodeConnection(node, model, dial, List.of(), List.of(), pinned, List.of());
				}
				return nodeConnection(node, model, dial, caKeys, List.of(node.name()), pinned, hostCerts);
			});
		});
	}

	private NodeConnectionInfo nodeConnection(Node node, NodeConnectionInfo.ConnectorModel model, String dial,
			List<byte[]> caKeys, List<String> principals, List<byte[]> pinned, List<byte[]> hostCerts) {
		NodeConnectionInfo info = new NodeConnectionInfo(model, node.name(), dial, caKeys, principals, pinned,
				hostCerts);
		// FR-CONN-5/7 (§9.3): an agentless node with no host-CA anchor and no pinned
		// key has no enrollment-anchored trust — the Gateway aborts (no TOFU). The
		// decision still ALLOWs; warn so the operator repairs the enrollment.
		if (model == NodeConnectionInfo.ConnectorModel.AGENTLESS && !info.hasHostVerification()) {
			LOG.warn("agentless node {} ({}) has no host-verification material (no host_ca keys, no pinned host "
					+ "keys); the Gateway will abort the session (no TOFU) — enroll a host cert or pin a host key",
					node.id(), node.name());
		}
		return info;
	}

	// HA routing (Design §10.2/§10.3; FR-HA-2/5): fold the FRESH presence owner
	// into
	// the connection for an outbound-agent node so the ingress Gateway routes to
	// the
	// owner (self ⇒ local S14 path; other ⇒ relay). Only a fresh owner counts — an
	// absent/stale owner means no live Gateway holds the agent channel, so the
	// fields
	// stay empty and the ingress fails closed to "node offline". Agentless nodes
	// have
	// no ownership (any Gateway dials directly), so they never carry owner fields.
	// The
	// nonce is the anti-stale fencing token the ingress binds into the relay token.
	private Mono<NodeConnectionInfo> attachFreshOwner(Node node, NodeConnectionInfo info) {
		if (info.connectorKind() != NodeConnectionInfo.ConnectorModel.OUTBOUND_AGENT) {
			return Mono.just(info);
		}
		Instant staleBefore = Instant.now().minus(haProperties.getPresenceStaleness());
		return presence.findById(node.id()).filter(owner -> owner.lastSeen().isAfter(staleBefore)).map(owner -> info
				.withOwner(owner.owningGateway(), owner.gatewayAddr(), owner.nonce(), owner.nonceId().toString()))
				.defaultIfEmpty(info);
	}

	// §9.2: the agentless dial address is "host:port". Inventory stores a reachable
	// address; if it carries no explicit port, default to SSH 22 (a bare IPv6
	// literal is bracketed first so the result is a valid host:port).
	private static String dialAddress(Node node) {
		String address = node.address();
		if (address == null || address.isBlank()) {
			return ""; // an agent node dials out and needs none (empty per the wire contract)
		}
		String trimmed = address.trim();
		if (hasExplicitPort(trimmed)) {
			return trimmed;
		}
		boolean bareIpv6 = !trimmed.startsWith("[") && trimmed.indexOf(':') != trimmed.lastIndexOf(':');
		return (bareIpv6 ? "[" + trimmed + "]" : trimmed) + ":22";
	}

	private static boolean hasExplicitPort(String address) {
		if (address.startsWith("[")) {
			return address.indexOf("]:") >= 0; // bracketed IPv6 with an explicit :port
		}
		int firstColon = address.indexOf(':');
		if (firstColon < 0 || firstColon != address.lastIndexOf(':')) {
			return false; // no colon (host/IPv4) or many colons (unbracketed IPv6) → no port
		}
		String port = address.substring(firstColon + 1);
		return !port.isEmpty() && port.chars().allMatch(Character::isDigit);
	}

	// An OpenSSH host public-key / TrustedUserCAKeys line is `<type> <base64>
	// [comment]`; the base64 middle token IS the SSH wire encoding. A malformed
	// line returns null and is dropped — fail-closed (dropped trust → the Gateway
	// aborts, never TOFU).
	private static byte[] wireBlob(String openSshLine) {
		if (openSshLine == null) {
			return null;
		}
		String[] fields = openSshLine.trim().split("\\s+");
		if (fields.length < 2) {
			return null;
		}
		try {
			return Base64.getDecoder().decode(fields[1]);
		} catch (IllegalArgumentException notBase64) {
			return null;
		}
	}

	private int effectiveGrantTtl(int grantTtlSeconds) {
		long ceiling = properties.getMaxGrantTtl().toSeconds();
		long chosen = grantTtlSeconds > 0 ? Math.min(grantTtlSeconds, ceiling) : ceiling;
		return (int) Math.min(chosen, Integer.MAX_VALUE);
	}

	private Mono<ConnectDecision> denyMissingInput(UUID callerGatewayId, String identity, UUID nodeId,
			String sourceIp) {
		return auditDeny(callerGatewayId, identity, nodeId, sourceIp,
				DataPlaneDecision.deny(DataPlaneDecision.Reason.EVALUATION_ERROR, null, null), "missing_input", null,
				null).thenReturn(ConnectDecision.denied());
	}

	// The deny path has no session (sessionId stays null, §8.4), but it still
	// populates source_ip/access_model/correlation_id where the caller knows them —
	// so a denied JIT/break-glass attempt is searchable by the same dimensions and
	// joins its correlation chain (FR-AUD-8).
	private Mono<Void> auditDeny(UUID callerGatewayId, String identity, UUID nodeId, String sourceIp,
			DataPlaneDecision decision, String note, String accessModel, UUID correlationId) {
		Map<String, String> detail = new HashMap<>();
		detail.put("reason", decision.reason().name());
		if (sourceIp != null) {
			detail.put("source_ip", sourceIp); // forensics: which source was denied
		}
		if (decision.matchedRuleName() != null) {
			detail.put("matched_rule", decision.matchedRuleName());
		}
		if (note != null) {
			detail.put("note", note);
		}
		return bestEffortAudit(AuditRecord.builder(actor(callerGatewayId), identity, DECISION_ACTION, "denied")
				.node(nodeId).detail(detail).sourceIp(auditableIp(sourceIp)).accessModel(accessModel)
				.correlationId(correlationId).build());
	}

	private Mono<Void> auditError(UUID callerGatewayId, String identity, UUID nodeId, String sourceIp) {
		Map<String, String> detail = new HashMap<>();
		detail.put("reason", DataPlaneDecision.Reason.EVALUATION_ERROR.name());
		if (sourceIp != null) {
			detail.put("source_ip", sourceIp);
		}
		return bestEffortAudit(AuditRecord.builder(actor(callerGatewayId), identity, DECISION_ACTION, "error")
				.node(nodeId).detail(detail).sourceIp(auditableIp(sourceIp)).build());
	}

	// A lost decision-log write must not fail the (already fail-closed) deny, but
	// it
	// MUST be observable — a silent audit gap on the deny path defeats FR-AUD-7.
	private Mono<Void> bestEffortAudit(AuditRecord record) {
		return audit.record(record).onErrorResume(auditFailure -> {
			LOG.error("authz decision-log write failed (decision still denied): {}", auditFailure.toString());
			return Mono.empty();
		});
	}

	// source_ip carries a DB CHECK (is_ip_or_cidr == ::inet); a value that ::inet
	// would reject is dropped from the COLUMN (kept in detail for forensics) so a
	// malformed source can never fail the audit insert — which on the allow path
	// would roll the connect back to a fail-closed deny, and on the deny path would
	// lose the decision-log row. AuditSourceIp is strict AND non-resolving (no DNS
	// on the event loop).
	private static String auditableIp(String sourceIp) {
		return AuditSourceIp.isCanonicalLiteral(sourceIp) ? sourceIp : null;
	}

	private static String actor(UUID callerGatewayId) {
		return callerGatewayId == null ? "unknown" : callerGatewayId.toString();
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	private static String nullSafe(String value) {
		return value == null ? "" : value;
	}

	// A node's resolved labels are a jsonb object of string->string; coerce values
	// to text (a non-string label value simply stringifies).
	private static Map<String, String> labelsOf(JsonNode resolvedLabels) {
		Map<String, String> labels = new HashMap<>();
		if (resolvedLabels != null && resolvedLabels.isObject()) {
			for (var entry : resolvedLabels.properties()) {
				labels.put(entry.getKey(), entry.getValue().asString());
			}
		}
		return labels;
	}

	// The signed context's node labels: "key=value" strings sorted so the signed
	// bytes are deterministic for the Gateway's local label-lock matching (S10).
	private static List<String> sortedLabelStrings(JsonNode resolvedLabels) {
		return labelsOf(resolvedLabels).entrySet().stream().map(e -> e.getKey() + "=" + e.getValue()).sorted().toList();
	}
}
