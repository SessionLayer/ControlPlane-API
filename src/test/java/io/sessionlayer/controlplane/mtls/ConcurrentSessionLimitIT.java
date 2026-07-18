package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.breakglass.BreakglassCredentialService;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicy;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.BreakglassResolution;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.OuterLegAuthGrpc;
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassKeyRequest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * FR-SESS-3 — the per-identity concurrent-session limit enforced at
 * {@code Authorize} over the purpose-built seam: leases in
 * {@code runtime.session_lease}, per-identity overrides in
 * {@code config.session_limit_policy}, cluster default in
 * {@code operator_settings.default_max_concurrent_sessions}. Proves the (N+1)th
 * session is refused with the generic deny and the
 * {@code concurrent_session_limit} decision-log note; a per-identity policy
 * overrides (and out-restricts) the cluster default; a lease acquired by a
 * <b>different</b> Gateway counts toward the cap (HA-correctness); releasing a
 * lease frees a slot; and break-glass is exempt and consumes no lease.
 */
class ConcurrentSessionLimitIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final String SOURCE_IP = "203.0.113.9";

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private SessionLeaseRepository sessionLeases;
	@Autowired
	private SessionLimitPolicyRepository sessionLimitPolicies;
	@Autowired
	private AuditEventStore auditStore;
	@Autowired
	private BreakglassCredentialService breakglassCredentials;

	@Test
	void theNPlusFirstConcurrentSessionIsDeniedWithTheConcurrentLimitNote() {
		String identity = "cap-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, 2);
		EnrolledGateway gateway = enroll("gw-cap-" + unique());

		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);

		AuthorizeResponse third = authorize(gateway, identity, nodeId, "deploy");
		assertThat(third.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(third.getSessionToken()).isEmpty();
		assertThat(third.hasContext()).isFalse();

		// Exactly two live leases were acquired; the refused one took none (deny wins).
		assertThat(countLive(identity)).isEqualTo(2);

		AuditEvent deny = deniedDecision(identity);
		assertThat(deny.detail().get("note").stringValue()).isEqualTo("concurrent_session_limit");
		assertThat(deny.detail().get("active_sessions").stringValue()).isEqualTo("2");
		assertThat(deny.detail().get("limit").stringValue()).isEqualTo("2");
	}

	// C1 (redteam MEDIUM): the cap is HARD, not soft. A concurrent BURST of
	// Authorizes
	// for ONE identity at cap L admits EXACTLY L — never more — because the
	// per-identity
	// advisory xact lock serializes count-then-acquire, so a shared/stolen
	// credential
	// can't overshoot the concurrent blast radius. This is the race the sequential
	// tests
	// cannot exercise; without serialization the burst would overshoot.
	@Test
	void aConcurrentBurstForOneIdentityNeverOvershootsTheCap() throws Exception {
		String identity = "burst-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		int limit = 2;
		seedPolicy(identity, limit);
		EnrolledGateway gateway = enroll("gw-burst-" + unique());

		int burst = 8;
		ExecutorService pool = Executors.newFixedThreadPool(burst);
		try {
			CountDownLatch ready = new CountDownLatch(burst);
			CountDownLatch go = new CountDownLatch(1);
			List<Future<Decision>> futures = new ArrayList<>();
			for (int i = 0; i < burst; i++) {
				futures.add(pool.submit(() -> {
					ready.countDown();
					go.await();
					return authorize(gateway, identity, nodeId, "deploy").getDecision();
				}));
			}
			assertThat(ready.await(15, TimeUnit.SECONDS)).isTrue();
			go.countDown(); // release the whole burst simultaneously

			long allows = 0;
			for (Future<Decision> future : futures) {
				if (future.get(30, TimeUnit.SECONDS) == Decision.DECISION_ALLOW) {
					allows++;
				}
			}
			assertThat(allows).isEqualTo(limit); // EXACTLY the cap — the race never overshoots
			assertThat(countLive(identity)).isEqualTo(limit);
		} finally {
			pool.shutdownNow();
		}
	}

	// A per-identity session_limit_policy overrides the cluster default — and here
	// it
	// out-restricts it (policy 2 < default 3); an identity with no policy falls to
	// the
	// default.
	@Test
	void aPerIdentityPolicyOverridesTheClusterDefault() {
		String policied = "policy-" + unique();
		String defaulted = "default-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(policied, nodeId, List.of("deploy"), List.of("shell"));
		seedAllow(defaulted, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(policied, 2);
		EnrolledGateway gateway = enroll("gw-policy-" + unique());

		setClusterDefault(3);
		try {
			// The policied identity is capped at 2 (policy wins over the default 3).
			authorize(gateway, policied, nodeId, "deploy");
			authorize(gateway, policied, nodeId, "deploy");
			assertThat(authorize(gateway, policied, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);

			// The no-policy identity is governed by the cluster default (3): three succeed,
			// the fourth is refused.
			authorize(gateway, defaulted, nodeId, "deploy");
			authorize(gateway, defaulted, nodeId, "deploy");
			assertThat(authorize(gateway, defaulted, nodeId, "deploy").getDecision())
					.isEqualTo(Decision.DECISION_ALLOW);
			assertThat(authorize(gateway, defaulted, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);
		} finally {
			clearClusterDefault();
		}
	}

	// HA-correctness: leases are counted per-identity over the shared datastore,
	// not
	// per-Gateway. A lease acquired by a DIFFERENT Gateway is decisive — with it
	// present the caller Gateway's first Authorize tips the identity over the cap;
	// a
	// naive per-Gateway count (blind to the peer's lease) would allow.
	@Test
	void aLeaseFromADifferentGatewayCountsTowardTheCap() {
		String identity = "ha-" + unique();
		UUID nodeId = seedProdNode();
		Node node = nodes.findById(nodeId).block();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, 2);
		EnrolledGateway peer = enroll("gw-ha-peer-" + unique());
		EnrolledGateway caller = enroll("gw-ha-caller-" + unique());

		// A live session + lease for this identity owned by a DIFFERENT Gateway (as if
		// written by another HA instance to the shared CP DB).
		SshSession peerSession = sshSessions.save(SshSession.create(identity, nodeId, node.name(), "deploy",
				peer.gatewayId(), "gw-ha-peer", "standing", List.of("shell"), null, "peer-rule", null, null, 0L,
				Instant.now().plusSeconds(3600), Instant.now())).block();
		sessionLeases.save(SessionLease.acquire(identity, peerSession.id(), "gw-ha-peer", Instant.now(),
				Instant.now().plusSeconds(3600))).block();

		// Cap is 2. With the peer lease counting, the caller's first Authorize is
		// allowed
		// (2 live) and the second is refused.
		assertThat(authorize(caller, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(caller, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	@Test
	void releasingALeaseFreesASlot() {
		String identity = "free-slot-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, 2);
		EnrolledGateway gateway = enroll("gw-free-" + unique());

		authorize(gateway, identity, nodeId, "deploy");
		authorize(gateway, identity, nodeId, "deploy");
		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);

		// Release one lease (the finalize path does this in prod; here we drive the
		// same
		// repository release directly by the session id).
		UUID sessionId = sshSessions.findByIdentity(identity).blockFirst().id();
		sessionLeases.releaseBySessionId(sessionId, Instant.now()).block();
		assertThat(countLive(identity)).isEqualTo(1);

		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);
	}

	// A leaked lease self-heals at grant_expiry: an unreleased lease whose
	// expires_at
	// is already in the past (a crashed session that never finalized) no longer
	// counts,
	// so it can never lock the identity out permanently — no reaper needed for
	// correctness.
	@Test
	void anExpiredUnreleasedLeaseNoLongerCountsTowardTheCap() {
		String identity = "leak-" + unique();
		UUID nodeId = seedProdNode();
		Node node = nodes.findById(nodeId).block();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, 1); // cap of one
		EnrolledGateway gateway = enroll("gw-leak-" + unique());

		// A leaked lease: unreleased but past its expires_at grant window.
		SshSession stale = sshSessions.save(SshSession.create(identity, nodeId, node.name(), "deploy",
				gateway.gatewayId(), "gw-leak", "standing", List.of("shell"), null, "stale-rule", null, null, 0L,
				Instant.now().minusSeconds(60), Instant.now().minusSeconds(3600))).block();
		sessionLeases.save(SessionLease.acquire(identity, stale.id(), "gw-leak", Instant.now().minusSeconds(3600),
				Instant.now().minusSeconds(60))).block();
		assertThat(countLive(identity)).isEqualTo(0); // the phantom lease is not counted

		// Even at cap 1, a new session is admitted; the fresh (unexpired) lease then
		// caps
		// the next one.
		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(gateway, identity, nodeId, "deploy").getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	// Break-glass is exempt: even with the identity already at its cap, a
	// break-glass
	// Authorize still allows AND consumes no lease (emergency access is neither
	// throttled by the cap nor eats into the normal budget).
	@Test
	void breakGlassIsExemptFromTheCapAndConsumesNoLease() throws Exception {
		String identity = "bg-cap-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("root"), List.of("shell"));
		seedPolicy(identity, 2);
		byte[] sk = skBlob((byte) 0x55);
		breakglassCredentials.register(sk, identity, List.of("root"), null, null, "admin").block();
		EnrolledGateway gateway = enroll("gw-bgcap-" + unique());

		authorize(gateway, identity, nodeId, "root");
		authorize(gateway, identity, nodeId, "root");
		assertThat(authorize(gateway, identity, nodeId, "root").getDecision()).isEqualTo(Decision.DECISION_DENY);

		BreakglassResolution resolution = resolveKey(gateway, sk, nodeId);
		assertThat(resolution.getBreakglassToken()).isNotBlank();
		assertThat(authorizeBreakglass(gateway, identity, nodeId, resolution.getBreakglassToken()).getDecision())
				.isEqualTo(Decision.DECISION_ALLOW);

		// The break-glass session took no lease — the count is still just the two
		// standing sessions.
		assertThat(countLive(identity)).isEqualTo(2);
	}

	// ----------------------- helpers -----------------------

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId, String principal) {
		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
				.setRequestedPrincipal(principal).setSourceIp(SOURCE_IP).setSessionId(UUID.randomUUID().toString())
				.build();
		return onChannel(gateway, channel -> AuthorizationGrpc.newBlockingStub(channel).authorize(request));
	}

	private AuthorizeResponse authorizeBreakglass(EnrolledGateway gateway, String identity, UUID nodeId, String token) {
		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
				.setRequestedPrincipal("root").setSourceIp(SOURCE_IP).setSessionId(UUID.randomUUID().toString())
				.setBreakglassToken(token).build();
		return onChannel(gateway, channel -> AuthorizationGrpc.newBlockingStub(channel).authorize(request));
	}

	private BreakglassResolution resolveKey(EnrolledGateway gateway, byte[] sk, UUID nodeId) {
		return onChannel(gateway,
				channel -> OuterLegAuthGrpc.newBlockingStub(channel)
						.resolveBreakglassKey(
								ResolveBreakglassKeyRequest.newBuilder().setSkPublicKeyBlob(ByteString.copyFrom(sk))
										.setSourceIp(SOURCE_IP).setNodeId(nodeId.toString()).build())
						.getResolution());
	}

	private long countLive(String identity) {
		return sessionLeases.countLiveByIdentity(identity, Instant.now()).block();
	}

	private AuditEvent deniedDecision(String identity) {
		return auditStore.search(new AuditQuery(null, identity, "authz.decision", "denied", null, null, null, null,
				null, null, null, Map.of(), null, List.of(), null, 50)).block().items().stream().findFirst()
				.orElseThrow();
	}

	private void setClusterDefault(int limit) {
		db.sql("UPDATE config.operator_settings SET default_max_concurrent_sessions = :n WHERE singleton = true")
				.bind("n", limit).fetch().rowsUpdated().block();
	}

	private void clearClusterDefault() {
		db.sql("UPDATE config.operator_settings SET default_max_concurrent_sessions = NULL WHERE singleton = true")
				.fetch().rowsUpdated().block();
	}

	private <T> T onChannel(EnrolledGateway gateway, java.util.function.Function<ManagedChannel, T> call) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return call.apply(channel);
		} finally {
			shutdown(channel);
		}
	}

	private UUID seedProdNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedAllow(String identity, UUID nodeId, List<String> principals, List<String> capabilities) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, principals, 3600,
				capabilities, "allow", "api")).block();
	}

	private void seedPolicy(String identity, int maxConcurrentSessions) {
		ObjectNode selector = JSON.objectNode();
		selector.set("identities", JSON.arrayNode().add(identity));
		sessionLimitPolicies.save(
				SessionLimitPolicy.create("limit-" + unique(), selector, maxConcurrentSessions, null, null, "api"))
				.block();
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

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
