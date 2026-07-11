package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateResponse;
import io.sessionlayer.controlplane.testnode.TestSshNode;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.testcontainers.containers.GenericContainer;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Part D — the full connect chain end to end against the Debian 13 Docker node
 * (never host ssh). An <b>allow</b> decision → minted token → S4
 * {@code SignSessionCertificate} → the node accepts the inner-leg cert in a
 * real SSH handshake; a <b>deny</b> decision → no token → signing is refused.
 * The inner keypair is generated <b>inside</b> the container (D2: the CP only
 * ever sees the public key).
 */
class AuthorizeNodeIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;
	@Autowired
	private CaSignerService caSigner;

	@Test
	void allowSignsACertTheNodeAcceptsAndDenyIsRefused() throws Exception {
		String caLine = caSigner.activeSigner("session").block().caAuthorizedKey("session-ca");
		try (GenericContainer<?> node = TestSshNode.start(caLine)) {
			EnrolledGateway gateway = enroll("gw-node-" + unique());
			UUID nodeId = seedProdNode();

			// ----- ALLOW: decision → token → sign → real handshake accepts -----
			String allowed = "alice-" + unique();
			seedAllow(allowed, "deploy", List.of("shell", "exec"));
			UUID sessionId = UUID.randomUUID();
			AuthorizeResponse allow = authorize(gateway, allowed, nodeId, "deploy", sessionId);
			assertThat(allow.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
			assertThat(allow.getSessionToken()).isNotBlank();

			byte[] subjectPublicKey = TestSshNode.generateInnerKey(node, "/tmp/inner");
			SignSessionCertificateResponse signed = signSessionCertificate(gateway, allow.getSessionToken(),
					subjectPublicKey, null);
			TestSshNode.installCertificate(node, "/tmp/inner-cert.pub", signed.getCertificateLine());
			String handshake = TestSshNode.handshake(node, "/tmp/inner", "/tmp/inner-cert.pub", "deploy");
			assertThat(handshake).contains("HANDSHAKE_OK");

			// ----- DENY: no matching rule → no token → signing refused -----
			AuthorizeResponse deny = authorize(gateway, "stranger-" + unique(), nodeId, "deploy", UUID.randomUUID());
			assertThat(deny.getDecision()).isEqualTo(Decision.DECISION_DENY);
			assertThat(deny.getSessionToken()).isEmpty();

			byte[] denyKey = TestSshNode.generateInnerKey(node, "/tmp/deny");
			StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
					() -> signSessionCertificate(gateway, deny.getSessionToken(), denyKey, null));
			assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
		}
	}

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId, String principal,
			UUID sessionId) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			// No source IP here: the in-container `ssh localhost` may connect over IPv6
			// (::1) or IPv4 loopback, so pinning the cert's source-address to one of them
			// is environment-dependent. This E2E proves the decision→token→sign→handshake
			// chain; the source-address reducer is proven in the unit tests (Selectors/
			// Cidrs) instead.
			return AuthorizationGrpc.newBlockingStub(channel)
					.authorize(AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
							.setRequestedPrincipal(principal).setSessionId(sessionId.toString()).build());
		} finally {
			shutdown(channel);
		}
	}

	private UUID seedProdNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedAllow(String identity, String principal, List<String> capabilities) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, List.of(principal), 3600,
				capabilities, "allow", "api")).block();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
