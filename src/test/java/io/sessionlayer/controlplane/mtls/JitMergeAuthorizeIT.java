package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.breakglass.BreakglassCredentialService;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.JitPolicy;
import io.sessionlayer.controlplane.data.config.JitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.data.runtime.JitRequest;
import io.sessionlayer.controlplane.data.runtime.JitRequestRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.grpc.v1.AccessModel;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.BreakglassResolution;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.DecisionContext;
import io.sessionlayer.controlplane.grpc.v1.OuterLegAuthGrpc;
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassKeyRequest;
import io.sessionlayer.controlplane.jit.JitException;
import io.sessionlayer.controlplane.jit.JitLifecycleService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * S30/OBS-1 — the §1.1-E regression matrix for the JIT/standing UNION
 * restructure: an approved, in-window JIT grant is now folded into the SAME
 * evaluation as standing access (never gated on a prior standing failure), so
 * it can widen a connect even when standing already matches something (just not
 * enough). Every deny-wins/break-glass/self-approval/attribution invariant is
 * proven here, not assumed — see
 * {@code ConnectAuthorizationService#resolveDecision}.
 */
class JitMergeAuthorizeIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final String SOURCE_IP = "203.0.113.9";

	@Autowired
	private JitLifecycleService jit;
	@Autowired
	private JitPolicyRepository policies;
	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;
	@Autowired
	private AccessLockRepository accessLocks;
	@Autowired
	private JitRequestRepository jitRequests;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private AuditEventRepository auditEvents;
	@Autowired
	private BreakglassCredentialService breakglassCredentials;

	// (1) OBS-1 headline: standing allows deploy only; a separate APPROVED JIT
	// grant for root elevates a request for root via the union, WITHOUT
	// disturbing the pre-existing deploy standing rule.
	@Test
	void aJitGrantForADifferentPrincipalElevatesEvenWhenStandingMatchesTheIdentity() throws Exception {
		String identity = "alice-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec"), 3600);
		seedZeroChainPolicy(zone, 1800, List.of("shell", "exec"));
		JitRequest grant = jit.submit(identity, nodeId, "root", List.of("shell", "exec"), "prod fix").block();
		assertThat(grant.state()).isEqualTo(JitRequest.APPROVED);

		EnrolledGateway gateway = enroll("gw-obs1-" + unique());
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "root", UUID.randomUUID());
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		DecisionContext ctx = DecisionContext.parseFrom(response.getSignedContext());
		assertThat(ctx.getAccessModel()).isEqualTo(AccessModel.ACCESS_MODEL_JIT);
		assertThat(ctx.getAllowedLoginsList()).containsExactlyInAnyOrder("deploy", "root");
		assertThat(jitRequests.findById(grant.id()).block().state()).isEqualTo(JitRequest.ACTIVE);

		// The pre-existing standing rule is untouched: a fresh connect as "deploy"
		// still resolves via standing alone (the root grant's principal never matches).
		UUID deploySessionId = UUID.randomUUID();
		AuthorizeResponse asDeploy = authorize(gateway, identity, nodeId, "deploy", deploySessionId);
		assertThat(asDeploy.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		// STANDING is the wire-compat default (absent field, N-1 Gateway safe — §16
		// D15), so assert via the persisted decision snapshot, not the proto enum.
		assertThat(sshSessions.findById(deploySessionId).block().accessModel()).isEqualTo("standing");
	}

	// (2) standing already matches the requested principal; a JIT grant for the
	// SAME principal ADDS a capability standing doesn't have — the union's
	// capability set, not just its login set, must widen.
	@Test
	void aJitGrantWidensCapabilitiesEvenWhenStandingAlreadyMatchesThePrincipal() throws Exception {
		String identity = "bob-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec"), 3600);
		seedZeroChainPolicy(zone, 1800, List.of("sftp"));
		JitRequest grant = jit.submit(identity, nodeId, "deploy", List.of("sftp"), "need sftp").block();
		assertThat(grant.state()).isEqualTo(JitRequest.APPROVED);

		EnrolledGateway gateway = enroll("gw-widen-" + unique());
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", sessionId);

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		DecisionContext ctx = DecisionContext.parseFrom(response.getSignedContext());
		assertThat(ctx.getAccessModel()).isEqualTo(AccessModel.ACCESS_MODEL_JIT);
		SshSession session = sshSessions.findById(sessionId).block();
		assertThat(session.capabilities()).containsExactlyInAnyOrder("shell", "exec", "sftp");
		assertThat(session.jitRequestId()).isEqualTo(grant.id());
		assertThat(jitRequests.findById(grant.id()).block().state()).isEqualTo(JitRequest.ACTIVE);
	}

	// (3) the common case: standing allows, no JIT grant exists at all (the
	// unconditional lookup now always runs, but changes nothing).
	@Test
	void standingAloneIsUnchangedWhenNoUsableGrantExists() {
		String identity = "carol-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec"), 3600);
		seedZeroChainPolicy(zone, 1800, List.of("shell", "exec")); // a policy exists, but no request was submitted

		EnrolledGateway gateway = enroll("gw-common-" + unique());
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", sessionId);

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		SshSession session = sshSessions.findById(sessionId).block();
		// STANDING is the wire-compat default (absent field, N-1 Gateway safe — §16
		// D15), so assert via the persisted decision snapshot, not the proto enum.
		assertThat(session.accessModel()).isEqualTo("standing");
		assertThat(session.jitRequestId()).isNull();
		assertThat(session.capabilities()).containsExactlyInAnyOrder("shell", "exec");
	}

	// (4) a usable grant exists but contributes NOTHING beyond what standing
	// already grants — it must stay APPROVED, unconsumed, for a connect that
	// actually needs it.
	@Test
	void aRedundantJitGrantIsNotConsumed() {
		String identity = "dave-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec"), 3600);
		seedZeroChainPolicy(zone, 1800, List.of("shell"));
		JitRequest grant = jit.submit(identity, nodeId, "deploy", List.of("shell"), "belt and suspenders").block();
		assertThat(grant.state()).isEqualTo(JitRequest.APPROVED);

		EnrolledGateway gateway = enroll("gw-redundant-" + unique());
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", sessionId);

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		SshSession session = sshSessions.findById(sessionId).block();
		// STANDING is the wire-compat default (absent field, N-1 Gateway safe — §16
		// D15), so assert via the persisted decision snapshot, not the proto enum.
		assertThat(session.accessModel()).isEqualTo("standing");
		assertThat(session.jitRequestId()).isNull();
		// The grant is untouched — still APPROVED, available for a later connect.
		assertThat(jitRequests.findById(grant.id()).block().state()).isEqualTo(JitRequest.APPROVED);
	}

	// (5) deny-wins over JIT: a Lock on the JIT-approved principal denies even
	// though standing doesn't cover it at all and a usable grant exists.
	@Test
	void aLockOnTheJitApprovedPrincipalStillDeniesEvenWithNoStandingCoverage() {
		String identity = "erin-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedZeroChainPolicy(zone, 1800, List.of("shell", "exec"));
		JitRequest grant = jit.submit(identity, nodeId, "root", List.of("shell"), "incident fix").block();
		// A "principal" facet is unscoped by identity/node (matches ANY connect
		// requesting that login, per LockMatching's OR-across-facets semantics) — the
		// shared Postgres container spans every test in this class, so the lock is
		// deleted at the end to avoid leaking into a sibling test that also requests
		// "root".
		AccessLock lock = accessLocks.save(AccessLock.create(JSON.objectNode().put("principal", "root"), "strict", null,
				null, "incident", "tester")).block();
		try {
			EnrolledGateway gateway = enroll("gw-lockprincipal-" + unique());
			AuthorizeResponse response = authorize(gateway, identity, nodeId, "root", UUID.randomUUID());

			assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
			assertThat(response.getSessionToken()).isEmpty();
			assertThat(jitRequests.findById(grant.id()).block().state()).isEqualTo(JitRequest.APPROVED);
			AuditEvent deny = latestDenyByCorrelation(grant.id());
			assertThat(deny.detail().get("reason").stringValue()).isEqualTo("LOCKED");
		} finally {
			accessLocks.deleteById(lock.id()).block();
		}
	}

	// (6) deny-wins over JIT: an explicit standing deny is terminal regardless of
	// a usable JIT grant for the same principal — the single most important
	// regression test in this session.
	@Test
	void anExplicitStandingDenyStillWinsOverAUsableJitGrant() {
		String identity = "frank-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedZeroChainPolicy(zone, 1800, List.of("shell", "exec"));
		JitRequest grant = jit.submit(identity, nodeId, "deploy", List.of("shell"), "fix").block();
		ObjectNode denySelector = JSON.objectNode();
		denySelector.set("identities", JSON.arrayNode().add(identity));
		dpRules.save(DpRule.create("deny-" + unique(), denySelector, JSON.objectNode(), null, List.of(), 3600,
				List.of(), "deny", "api")).block();

		EnrolledGateway gateway = enroll("gw-explicitdeny-" + unique());
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", UUID.randomUUID());

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(jitRequests.findById(grant.id()).block().state()).isEqualTo(JitRequest.APPROVED);
		AuditEvent deny = latestDenyByCorrelation(grant.id());
		assertThat(deny.detail().get("reason").stringValue()).isEqualTo("EXPLICIT_DENY");
	}

	// (7) still fails without a grant: no standing match, no usable JIT grant.
	@Test
	void deniesWithNoStandingAndNoUsableGrant() {
		String identity = "gina-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);

		EnrolledGateway gateway = enroll("gw-nomatch-" + unique());
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", UUID.randomUUID());

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		AuditEvent deny = latestDenyBySubject(gateway, identity);
		assertThat(deny.detail().get("reason").stringValue()).isEqualTo("NO_MATCHING_ALLOW");
	}

	// (8) still fails, principal genuinely uncovered: the fix widens WHEN JIT is
	// consulted, never grants anything nobody approved.
	@Test
	void deniesWhenNoUsableGrantCoversTheRequestedPrincipal() {
		String identity = "hank-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec"), 3600);

		EnrolledGateway gateway = enroll("gw-uncovered-" + unique());
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "root", UUID.randomUUID());

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		AuditEvent deny = latestDenyBySubject(gateway, identity);
		assertThat(deny.detail().get("reason").stringValue()).isEqualTo("PRINCIPAL_NOT_ALLOWED");
	}

	// (9) break-glass untouched: the union logic is bypassed entirely — a usable
	// JIT grant sits there UNCONSUMED while break-glass decides the connect.
	@Test
	void breakglassBypassesTheUnionEntirelyAndNeverTouchesAUsableJitGrant() throws Exception {
		String identity = "ivan-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedZeroChainPolicy(zone, 1800, List.of("shell"));
		JitRequest grant = jit.submit(identity, nodeId, "root", List.of("shell"), "unrelated").block();
		// A fill byte distinct from every other skBlob() caller in the suite (shared
		// Postgres container ⇒ shared breakglass_credential.key_fingerprint UNIQUE
		// constraint across test classes).
		byte[] sk = skBlob((byte) 0x77);
		breakglassCredentials.register(sk, identity, List.of("root"), null, null, "admin").block();
		EnrolledGateway gateway = enroll("gw-bgunion-" + unique());

		BreakglassResolution resolution = resolveKey(gateway, sk, nodeId);
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "root", sessionId,
				resolution.getBreakglassToken());

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		DecisionContext ctx = DecisionContext.parseFrom(response.getSignedContext());
		assertThat(ctx.getAccessModel()).isEqualTo(AccessModel.ACCESS_MODEL_BREAKGLASS);
		SshSession session = sshSessions.findById(sessionId).block();
		assertThat(session.jitRequestId()).isNull();
		// The grant never entered the decision at all — still APPROVED.
		assertThat(jitRequests.findById(grant.id()).block().state()).isEqualTo(JitRequest.APPROVED);
	}

	// (10) self-approval is still impossible, and — specific to the unconditional
	// lookup this session introduces — a request stuck PENDING_APPROVAL (self-
	// approval rejected) is never returned as a usable grant by the merged path.
	@Test
	void selfApprovalRemainsImpossibleAndAPendingRequestNeverElevatesTheConnect() {
		String identity = "judy-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedChainPolicy(zone, 1800, level("email", identity)); // the requester is itself the configured approver
		JitRequest submitted = jit.submit(identity, nodeId, "deploy", List.of("shell"), "self").block();
		assertThat(submitted.state()).isEqualTo(JitRequest.PENDING_APPROVAL);

		JitException failure = catchThrowableOfType(JitException.class,
				() -> jit.approve(submitted.id(), identity, List.of(), "me").block());
		assertThat(failure.reason()).isEqualTo(JitException.Reason.SELF_APPROVAL);
		assertThat(jitRequests.findById(submitted.id()).block().state()).isEqualTo(JitRequest.PENDING_APPROVAL);

		EnrolledGateway gateway = enroll("gw-selfapproval-" + unique());
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", UUID.randomUUID());
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	// (11) TTL bound: even when a standing rule for the same principal carries a
	// very long TTL, a load-bearing JIT grant's shorter remaining TTL still
	// bounds the emitted grant_expiry (the engine's own min-positive-ttls
	// formula, now exercised across BOTH rule sets at once).
	@Test
	void aLoadBearingGrantBoundsTheTtlEvenWhenStandingHasAMuchLongerOne() throws Exception {
		String identity = "karl-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec"), 100_000);
		seedZeroChainPolicy(zone, 120, List.of("sftp"));
		JitRequest grant = jit.submit(identity, nodeId, "deploy", List.of("sftp"), "short-lived need").block();

		EnrolledGateway gateway = enroll("gw-ttlbound-" + unique());
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", UUID.randomUUID());

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		DecisionContext ctx = DecisionContext.parseFrom(response.getSignedContext());
		assertThat(ctx.getAccessModel()).isEqualTo(AccessModel.ACCESS_MODEL_JIT);
		long ttl = ctx.getGrantExpiryEpochSeconds() - Instant.now().getEpochSecond();
		// Bounded by the JIT grant's ~120s ceiling, nowhere near the standing rule's
		// 100,000s.
		assertThat(ttl).isBetween(1L, 130L);
		assertThat(jitRequests.findById(grant.id()).block().state()).isEqualTo(JitRequest.ACTIVE);
	}

	// (12) a merged (hybrid) session tears down exactly like a pure-JIT one: the
	// revoke-as-lock mechanism (S10) doesn't care how the grant became ACTIVE.
	@Test
	void revokeAsLockTearsDownAMergedSessionsGrantJustLikeAPureJitOne() {
		String identity = "linda-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec"), 3600);
		seedZeroChainPolicy(zone, 1800, List.of("sftp"));
		JitRequest grant = jit.submit(identity, nodeId, "deploy", List.of("sftp"), "temp sftp").block();

		EnrolledGateway gateway = enroll("gw-revoke-" + unique());
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", UUID.randomUUID());
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(jitRequests.findById(grant.id()).block().state()).isEqualTo(JitRequest.ACTIVE);

		JitRequest revoked = jit.revoke(grant.id(), "operator", "incident").block();
		assertThat(revoked.state()).isEqualTo(JitRequest.REVOKED);
		List<AccessLock> locks = accessLocks.findAll().collectList().block();
		assertThat(locks).anySatisfy(l -> assertThat(l.reason()).contains("jit revoked"));

		// The teardown lock is identity-scoped and short-lived, not session-scoped —
		// it blocks EVERY connect for this identity (standing included) until it
		// expires, exactly as it would for a pure-standing or pure-JIT session. This
		// is accessModel-blind by construction (LockMatching never reads accessModel),
		// proving provenance doesn't matter to the lock re-check (§ doctrine).
		AuthorizeResponse after = authorize(gateway, identity, nodeId, "deploy", UUID.randomUUID());
		assertThat(after.getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	// ----- helpers -----

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId, String principal,
			UUID sessionId) {
		return authorize(gateway, identity, nodeId, principal, sessionId, null);
	}

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId, String principal,
			UUID sessionId, String breakglassToken) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			AuthorizeRequest.Builder request = AuthorizeRequest.newBuilder().setIdentity(identity)
					.setNodeId(nodeId.toString()).setRequestedPrincipal(principal).setSessionId(sessionId.toString())
					.setSourceIp(SOURCE_IP);
			if (breakglassToken != null) {
				request.setBreakglassToken(breakglassToken);
			}
			return AuthorizationGrpc.newBlockingStub(channel).authorize(request.build());
		} finally {
			shutdown(channel);
		}
	}

	private BreakglassResolution resolveKey(EnrolledGateway gateway, byte[] sk, UUID nodeId) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return OuterLegAuthGrpc.newBlockingStub(channel)
					.resolveBreakglassKey(
							ResolveBreakglassKeyRequest.newBuilder().setSkPublicKeyBlob(ByteString.copyFrom(sk))
									.setSourceIp(SOURCE_IP).setNodeId(nodeId.toString()).build())
					.getResolution();
		} finally {
			shutdown(channel);
		}
	}

	// A structurally valid sk-ecdsa-sha2-nistp256 wire blob (public material only).
	private static byte[] skBlob(byte fill) {
		byte[] q = new byte[65];
		q[0] = 0x04;
		for (int i = 1; i < q.length; i++) {
			q[i] = fill;
		}
		return new SshWriter().writeString("sk-ecdsa-sha2-nistp256@openssh.com").writeString("nistp256").writeString(q)
				.writeString("ssh:").toByteArray();
	}

	private AuditEvent latestDenyByCorrelation(UUID correlationId) {
		return auditEvents.findByCorrelationId(correlationId).collectList().block().stream()
				.filter(e -> "authz.decision".equals(e.action()) && "denied".equals(e.outcome()))
				.reduce((first, second) -> second).orElseThrow();
	}

	private AuditEvent latestDenyBySubject(EnrolledGateway gateway, String identity) {
		return auditEvents.findByActor(gateway.gatewayId().toString()).collectList().block().stream()
				.filter(e -> identity.equals(e.subject()) && "authz.decision".equals(e.action())
						&& "denied".equals(e.outcome()))
				.reduce((first, second) -> second).orElseThrow();
	}

	// A per-test zone label so exactly one JIT policy governs this test's node
	// (the class shares one Postgres; policy matching takes the first matching
	// policy).
	private UUID seedNode(String zone) {
		ObjectNode labels = JSON.objectNode().put("env", "prod").put("jitzone", zone);
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedAllow(String identity, UUID nodeId, List<String> principals, List<String> capabilities,
			int ttlSeconds) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, principals, ttlSeconds,
				capabilities, "allow", "api")).block();
	}

	private void seedZeroChainPolicy(String zone, int maxTtl, List<String> capabilities) {
		policies.save(
				JitPolicy.create("jit-" + unique(), zoneSelector(zone), capabilities, maxTtl, JSON.arrayNode(), "api"))
				.block();
	}

	private void seedChainPolicy(String zone, int maxTtl, ObjectNode... levels) {
		ArrayNode chain = JSON.arrayNode();
		for (ObjectNode level : levels) {
			chain.add(level);
		}
		policies.save(
				JitPolicy.create("jit-" + unique(), zoneSelector(zone), List.of("shell", "exec"), maxTtl, chain, "api"))
				.block();
	}

	private static ObjectNode zoneSelector(String zone) {
		ObjectNode targetSelector = JSON.objectNode();
		targetSelector.set("jitzone", JSON.objectNode().put("op", "eq").put("value", zone));
		return targetSelector;
	}

	private static ObjectNode level(String kind, String value) {
		return JSON.objectNode().put("kind", kind).put("value", value);
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
