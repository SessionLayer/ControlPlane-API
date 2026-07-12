package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.breakglass.BreakglassCredentialService;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivationRepository;
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
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassCodeRequest;
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassKeyRequest;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Break-glass end to end (Part C/E, FR-ACC-6): a registered FIDO2 sk-ecdsa key
 * (or offline code) resolves over the outer-leg RPC to a single-use token; that
 * token at {@code Authorize} raises the activation + high-priority alert
 * UNCONDITIONALLY, forces {@code access_model = BREAKGLASS}, and allows SUBJECT
 * TO the top-tier Lock (a locked target still denies; the activation stands).
 */
class BreakglassAuthorizeIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final String SOURCE_IP = "203.0.113.7";

	@Autowired
	private BreakglassCredentialService credentials;
	@Autowired
	private BreakglassActivationRepository activations;
	@Autowired
	private NodeRepository nodes;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private AccessLockRepository accessLocks;
	@Autowired
	private AuditEventRepository auditEvents;

	@Test
	void keyResolvesThenAuthorizeAllowsWithActivationAndAlert() throws Exception {
		String identity = "bg-op-" + unique();
		byte[] sk = skBlob((byte) 0x31);
		credentials.register(sk, identity, List.of("root"), null, null, "admin").block();
		UUID nodeId = seedNode();
		EnrolledGateway gateway = enroll("gw-bg-" + unique());

		BreakglassResolution resolution = resolveKey(gateway, sk, nodeId);
		assertThat(resolution.getIdentity().getResolved()).isTrue();
		assertThat(resolution.getBreakglassToken()).isNotBlank();

		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "root", sessionId,
				resolution.getBreakglassToken());
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);

		DecisionContext ctx = DecisionContext.parseFrom(response.getSignedContext());
		assertThat(ctx.getAccessModel()).isEqualTo(AccessModel.ACCESS_MODEL_BREAKGLASS);

		SshSession session = sshSessions.findById(sessionId).block();
		assertThat(session.accessModel()).isEqualTo("breakglass");
		assertThat(session.breakglassActivationId()).isNotNull();

		BreakglassActivation activation = activations.findById(session.breakglassActivationId()).block();
		assertThat(activation.reviewStatus()).isEqualTo("pending");
		assertThat(activation.identity()).isEqualTo(identity);
		assertThat(activation.targetNodeId()).isEqualTo(nodeId);
		assertThat(activation.sourceIp()).isEqualTo(SOURCE_IP);

		// The high-priority alert fired (default audit-event sink).
		List<AuditEvent> alerts = auditEvents.findByActor("system:break-glass").collectList().block();
		assertThat(alerts).anySatisfy(e -> assertThat(e.action()).isEqualTo("breakglass.activated"));

		// The token is single-use: a replay is denied.
		AuthorizeResponse replay = authorize(gateway, identity, nodeId, "root", UUID.randomUUID(),
				resolution.getBreakglassToken());
		assertThat(replay.getDecision()).isEqualTo(Decision.DECISION_DENY);
	}

	@Test
	void offlineCodeResolvesSingleUse() {
		String identity = "bg-code-" + unique();
		var issued = credentials.issueOfflineCodes(identity, List.of("root"), null, null, 1, null, "admin").block();
		String code = issued.rawCodes().get(0);
		UUID nodeId = seedNode();
		EnrolledGateway gateway = enroll("gw-bgc-" + unique());

		assertThat(resolveCode(gateway, code, nodeId).getIdentity().getResolved()).isTrue();
		// Replay of the same code fails closed (single-use).
		assertThat(resolveCode(gateway, code, nodeId).getIdentity().getResolved()).isFalse();
	}

	@Test
	void lockedTargetRefusesBreakglassButActivationStands() throws Exception {
		String identity = "bg-locked-" + unique();
		byte[] sk = skBlob((byte) 0x42);
		credentials.register(sk, identity, List.of("root"), null, null, "admin").block();
		UUID nodeId = seedNode();
		accessLocks.save(AccessLock.create(JSON.objectNode().put("node_id", nodeId.toString()), "strict", null, null,
				"incident", "tester")).block();
		EnrolledGateway gateway = enroll("gw-bglock-" + unique());

		BreakglassResolution resolution = resolveKey(gateway, sk, nodeId);
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse response = authorize(gateway, identity, nodeId, "root", sessionId,
				resolution.getBreakglassToken());
		// A locked target refuses break-glass (deny wins).
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(response.getSessionToken()).isEmpty();

		// ...but the activation + alert STAND (a break-glass attempt is always
		// recorded).
		List<BreakglassActivation> pending = activations.findByReviewStatus("pending").collectList().block();
		assertThat(pending).anySatisfy(a -> {
			assertThat(a.identity()).isEqualTo(identity);
			assertThat(a.targetNodeId()).isEqualTo(nodeId);
		});
	}

	private BreakglassResolution resolveKey(EnrolledGateway gateway, byte[] sk, UUID nodeId) {
		return outerLeg(gateway,
				stub -> stub.resolveBreakglassKey(
						ResolveBreakglassKeyRequest.newBuilder().setSkPublicKeyBlob(ByteString.copyFrom(sk))
								.setSourceIp(SOURCE_IP).setNodeId(nodeId.toString()).build())
						.getResolution());
	}

	private BreakglassResolution resolveCode(EnrolledGateway gateway, String code, UUID nodeId) {
		return outerLeg(gateway, stub -> stub.resolveBreakglassCode(ResolveBreakglassCodeRequest.newBuilder()
				.setCode(code).setSourceIp(SOURCE_IP).setNodeId(nodeId.toString()).build()).getResolution());
	}

	private <T> T outerLeg(EnrolledGateway gateway,
			java.util.function.Function<OuterLegAuthGrpc.OuterLegAuthBlockingStub, T> call) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return call.apply(OuterLegAuthGrpc.newBlockingStub(channel));
		} finally {
			shutdown(channel);
		}
	}

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId, String principal,
			UUID sessionId, String breakglassToken) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return AuthorizationGrpc.newBlockingStub(channel)
					.authorize(AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
							.setRequestedPrincipal(principal).setSourceIp(SOURCE_IP).setSessionId(sessionId.toString())
							.setBreakglassToken(breakglassToken).build());
		} finally {
			shutdown(channel);
		}
	}

	private UUID seedNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
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
