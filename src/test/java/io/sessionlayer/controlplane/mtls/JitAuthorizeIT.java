package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.JitPolicy;
import io.sessionlayer.controlplane.data.config.JitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
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
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.DecisionContext;
import io.sessionlayer.controlplane.jit.JitLifecycleService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * The JIT two-pass Authorize wiring (Part E, FR-ACC-2). A standing default-deny
 * ({@code NO_MATCHING_ALLOW}) is elevated by an ACTIVE/APPROVED JIT grant: the
 * grant is synthesized as an in-memory allow and the engine is re-run, so a
 * Lock still wins (deny wins). An allow yields {@code access_model = JIT} in
 * the signed context and a grant_expiry bounded by the JIT TTL; the grant flips
 * to ACTIVE.
 */
class JitAuthorizeIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

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

	@Test
	void anApprovedJitGrantElevatesADefaultDeny() throws Exception {
		String identity = "alice-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedZeroChainPolicy(zone, 1800); // 30-min JIT grant, auto-approved
		JitRequest grant = jit.submit(identity, nodeId, "deploy", List.of("shell", "exec"), "prod fix").block();
		assertThat(grant.state()).isEqualTo(JitRequest.APPROVED);

		EnrolledGateway gateway = enroll("gw-jit-" + unique());
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", sessionId);

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		DecisionContext ctx = DecisionContext.parseFrom(response.getSignedContext());
		assertThat(ctx.getAccessModel()).isEqualTo(AccessModel.ACCESS_MODEL_JIT);
		assertThat(ctx.getAllowedLoginsList()).containsExactly("deploy");
		// grant_expiry reflects the JIT grant (bounded by the cred-TTL ceiling of 1h).
		long ttl = ctx.getGrantExpiryEpochSeconds() - Instant.now().getEpochSecond();
		assertThat(ttl).isBetween(1L, 3600L);

		SshSession session = sshSessions.findById(sessionId).block();
		assertThat(session.accessModel()).isEqualTo("jit");
		assertThat(session.jitRequestId()).isEqualTo(grant.id());
		// First use flips APPROVED → ACTIVE.
		assertThat(jitRequests.findById(grant.id()).block().state()).isEqualTo(JitRequest.ACTIVE);
	}

	@Test
	void aLockStillDeniesAJitGrant() {
		String identity = "bob-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedZeroChainPolicy(zone, 1800);
		jit.submit(identity, nodeId, "deploy", List.of("shell"), "fix").block();
		// A Lock on the node denies even a JIT-elevated connect (deny wins).
		accessLocks.save(AccessLock.create(JSON.objectNode().put("node_id", nodeId.toString()), "strict", null, null,
				"incident", "tester")).block();

		EnrolledGateway gateway = enroll("gw-jitlock-" + unique());
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", UUID.randomUUID());
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(response.getSessionToken()).isEmpty();
	}

	@Test
	void anExplicitStandingDenyIsNotElevatedByJit() {
		String identity = "carol-" + unique();
		String zone = unique();
		UUID nodeId = seedNode(zone);
		seedZeroChainPolicy(zone, 1800);
		jit.submit(identity, nodeId, "deploy", List.of("shell"), "fix").block();
		// An explicit deny is terminal in the FIRST pass, so JIT is never attempted.
		// dp_rule requires a non-null node_label_selector (an empty object matches any
		// node) and ttl_seconds > 0 — a deny grants nothing, so its TTL is never read.
		ObjectNode denySelector = JSON.objectNode();
		denySelector.set("identities", JSON.arrayNode().add(identity));
		dpRules.save(DpRule.create("deny-" + unique(), denySelector, JSON.objectNode(), null, List.of(), 3600,
				List.of(), "deny", "api")).block();

		EnrolledGateway gateway = enroll("gw-jitdeny-" + unique());
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "deploy", UUID.randomUUID());
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId, String principal,
			UUID sessionId) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return AuthorizationGrpc.newBlockingStub(channel)
					.authorize(AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
							.setRequestedPrincipal(principal).setSessionId(sessionId.toString()).build());
		} finally {
			shutdown(channel);
		}
	}

	// A per-test zone label so exactly one JIT policy governs this test's node (the
	// class shares one Postgres; policy matching takes the first matching policy).
	private UUID seedNode(String zone) {
		ObjectNode labels = JSON.objectNode().put("env", "prod").put("jitzone", zone);
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedZeroChainPolicy(String zone, int maxTtl) {
		ObjectNode targetSelector = JSON.objectNode();
		targetSelector.set("jitzone", JSON.objectNode().put("op", "eq").put("value", zone));
		policies.save(JitPolicy.create("jit-" + unique(), targetSelector, List.of("shell", "exec"), maxTtl,
				JSON.arrayNode(), "api")).block();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
