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
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * FR-SESS-3 — the per-identity concurrent-session limit enforced at
 * {@code Authorize}. With a small configured cap, the (N+1)th concurrent
 * session for one identity is refused with the generic deny while the decision
 * log records the {@code concurrent_session_limit} reason; a different identity
 * is unaffected; a session written by a <b>different</b> Gateway counts toward
 * the cap (HA-correctness — the count spans the fleet, not one Gateway);
 * closing a session frees a slot; a per-identity override changes the
 * threshold; and break-glass is exempt (emergency access is never throttled by
 * the cap).
 */
@TestPropertySource(properties = {"sessionlayer.authz.max-concurrent-sessions-per-identity=2",
		"sessionlayer.authz.concurrent-session-limit-overrides[bulk-identity]=4"})
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
	private AuditEventStore auditStore;
	@Autowired
	private BreakglassCredentialService breakglassCredentials;

	@Test
	void theNPlusFirstConcurrentSessionIsDeniedWithTheConcurrentLimitNote() {
		String identity = "cap-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-cap-" + unique());

		// Cap is 2: the first two succeed, the third is refused.
		assertThat(authorize(gateway, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(gateway, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_ALLOW);

		AuthorizeResponse third = authorize(gateway, identity, nodeId);
		assertThat(third.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(third.getSessionToken()).isEmpty();
		assertThat(third.hasContext()).isFalse();

		// Exactly the cap number of session rows were written — the refused one minted
		// nothing (deny wins, fail closed).
		assertThat(sshSessions.findByIdentity(identity).collectList().block()).hasSize(2);

		// The decision log records the specific server-side reason with the
		// count/limit.
		AuditEvent deny = deniedDecision(identity);
		assertThat(deny.detail().get("note").stringValue()).isEqualTo("concurrent_session_limit");
		assertThat(deny.detail().get("active_sessions").stringValue()).isEqualTo("2");
		assertThat(deny.detail().get("limit").stringValue()).isEqualTo("2");
	}

	@Test
	void adifferentIdentityIsUnaffectedByAnothersCap() {
		String capped = "capped-" + unique();
		String other = "free-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(capped, nodeId, List.of("deploy"), List.of("shell"));
		seedAllow(other, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-iso-" + unique());

		// Fill the first identity to its cap (2 allows + 1 deny).
		authorize(gateway, capped, nodeId);
		authorize(gateway, capped, nodeId);
		assertThat(authorize(gateway, capped, nodeId).getDecision()).isEqualTo(Decision.DECISION_DENY);

		// A different identity is counted independently — still allowed.
		assertThat(authorize(gateway, other, nodeId).getDecision()).isEqualTo(Decision.DECISION_ALLOW);
	}

	// HA-correctness: the count is identity-scoped over the shared datastore, not
	// per-Gateway. A session written by a DIFFERENT Gateway is decisive here — with
	// it present, the caller Gateway's own second Authorize tips the identity over
	// the
	// cap; a naive per-Gateway count (which could not see the peer's row) would
	// allow.
	@Test
	void aSessionFromADifferentGatewayCountsTowardTheCap() {
		String identity = "ha-" + unique();
		UUID nodeId = seedProdNode();
		Node node = nodes.findById(nodeId).block();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway peer = enroll("gw-ha-peer-" + unique());
		EnrolledGateway caller = enroll("gw-ha-caller-" + unique());

		// A live session for this identity owned by a DIFFERENT Gateway (as if written
		// by another HA instance to the shared CP DB).
		sshSessions.save(SshSession.create(identity, nodeId, node.name(), "deploy", peer.gatewayId(), "gw-ha-peer",
				"standing", List.of("shell"), null, "peer-rule", null, null, 0L, Instant.now().plusSeconds(3600),
				Instant.now())).block();

		// Cap is 2. With the peer row counting, the caller's first Authorize is allowed
		// (2 live) and the second is refused (would-be 3rd).
		assertThat(authorize(caller, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authorize(caller, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	@Test
	void closingASessionFreesASlot() {
		String identity = "free-slot-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-free-" + unique());

		authorize(gateway, identity, nodeId);
		authorize(gateway, identity, nodeId);
		assertThat(authorize(gateway, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_DENY);

		// End one live session (the finalize path does this via ssh_session.ended();
		// here we exercise the count predicate directly — ended_at IS NULL is the live
		// gate).
		SshSession live = sshSessions.findByIdentity(identity).blockFirst();
		sshSessions.save(live.ended(Instant.now(), "closed")).block();

		// The freed slot admits a new session for the same identity.
		assertThat(authorize(gateway, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_ALLOW);
	}

	@Test
	void aPerIdentityOverrideRaisesTheThreshold() {
		String identity = "bulk-identity"; // matches the configured override (limit 4)
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-override-" + unique());

		// The default is 2, but this identity's override is 4: four succeed, the fifth
		// is refused.
		for (int i = 0; i < 4; i++) {
			assertThat(authorize(gateway, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		}
		assertThat(authorize(gateway, identity, nodeId).getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	// Break-glass is exempt: even with the identity already at its cap, a
	// break-glass
	// Authorize still allows (emergency access must not be throttled by a routine
	// resource cap; it is gated instead by single-use token issuance + Lock
	// supremacy).
	@Test
	void breakGlassIsExemptFromTheCap() throws Exception {
		String identity = "bg-cap-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("root"), List.of("shell"));
		byte[] sk = skBlob((byte) 0x55);
		breakglassCredentials.register(sk, identity, List.of("root"), null, null, "admin").block();
		EnrolledGateway gateway = enroll("gw-bgcap-" + unique());

		// Fill the identity to its standing cap.
		authorize(gateway, identity, nodeId, "root");
		authorize(gateway, identity, nodeId, "root");
		assertThat(authorize(gateway, identity, nodeId, "root").getDecision()).isEqualTo(Decision.DECISION_DENY);

		// Break-glass over the cap still allows.
		BreakglassResolution resolution = resolveKey(gateway, sk, nodeId);
		assertThat(resolution.getBreakglassToken()).isNotBlank();
		AuthorizeResponse bg = authorizeBreakglass(gateway, identity, nodeId, resolution.getBreakglassToken());
		assertThat(bg.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
	}

	// ----------------------- helpers -----------------------

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId) {
		return authorize(gateway, identity, nodeId, "deploy");
	}

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

	private AuditEvent deniedDecision(String identity) {
		return auditStore.search(new AuditQuery(null, identity, "authz.decision", "denied", null, null, null, null,
				null, null, null, Map.of(), null, List.of(), null, 50)).block().items().stream().findFirst()
				.orElseThrow();
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
