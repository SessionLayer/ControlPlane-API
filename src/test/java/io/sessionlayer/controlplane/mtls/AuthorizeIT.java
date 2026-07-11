package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.authz.DecisionContextVerifier;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.Capability;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.DecisionContext;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateResponse;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Part B — the connect-time {@code Authorize} RPC over mTLS (FR-CHAN-1). An
 * allow returns a verifiable signed context + a minted session token that then
 * signs an inner-leg cert via the S4 signer (the wiring this session delivers);
 * a deny or a Lock returns a generic deny with no token (fail closed), and the
 * {@code ssh_session} decision snapshot is written on allow.
 */
class AuthorizeIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;
	@Autowired
	private AccessLockRepository accessLocks;
	@Autowired
	private SshSessionRepository sshSessions;

	@Test
	void allowReturnsSignedContextAndAMintedTokenThatSigns() throws Exception {
		String identity = "alice-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec", "sftp"));
		EnrolledGateway gateway = enroll("gw-authz-" + unique());
		UUID sessionId = UUID.randomUUID();

		AuthorizeResponse response = authorize(gateway, request(identity, nodeId, "deploy", "10.0.0.5", sessionId));

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(response.getSessionToken()).isNotBlank();

		// The signed context verifies against the internal mTLS CA (S10 reference
		// path).
		assertThat(DecisionContextVerifier.verify(caCertificate(), response.getSignerCertificate().toByteArray(),
				response.getSignedContext().toByteArray(), response.getSignature().toByteArray())).isTrue();

		DecisionContext parsed = DecisionContext.parseFrom(response.getSignedContext());
		assertThat(parsed.getNodeId()).isEqualTo(nodeId.toString());
		assertThat(parsed.getPrincipal()).isEqualTo("deploy");
		assertThat(parsed.getAllowedLoginsList()).containsExactly("deploy");
		assertThat(parsed.getCapabilitiesList()).contains(Capability.CAPABILITY_SHELL, Capability.CAPABILITY_SFTP);
		assertThat(parsed.getSessionId()).isEqualTo(sessionId.toString());
		assertThat(parsed.getDecisionTtlSeconds()).isBetween(30L, 60L);

		// The decision snapshot was written (survives config GC).
		SshSession snapshot = sshSessions.findById(sessionId).block();
		assertThat(snapshot).isNotNull();
		assertThat(snapshot.principal()).isEqualTo("deploy");
		assertThat(snapshot.accessModel()).isEqualTo("standing");
		assertThat(snapshot.matchedRuleName()).isNotNull();

		// The minted token signs an inner-leg cert via the S4 SessionSigning RPC.
		KeyPair inner = MtlsTestSupport.generateEcKeyPair();
		SignSessionCertificateResponse signed = signSessionCertificate(gateway, response.getSessionToken(),
				MtlsTestSupport.opensshPublicKeyBlob((ECPublicKey) inner.getPublic()), null);
		assertThat(signed.getCertificateLine()).startsWith("ecdsa-sha2-nistp256-cert-v01@openssh.com");
		assertThat(signed.getKeyId()).isEqualTo(sessionId + "+deploy");
	}

	@Test
	void noMatchingAllowDeniesWithNoToken() {
		String identity = "nobody-" + unique();
		UUID nodeId = seedProdNode();
		EnrolledGateway gateway = enroll("gw-deny-" + unique());

		AuthorizeResponse response = authorize(gateway,
				request(identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID()));
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(response.getSessionToken()).isEmpty();
		assertThat(response.hasContext()).isFalse();
	}

	@Test
	void aMatchingLockDeniesWithNoTokenEvenWithAnAllow() {
		String identity = "locked-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		accessLocks.save(AccessLock.create(JSON.objectNode().put("identity", identity), "strict", null, null,
				"incident", "tester")).block();
		EnrolledGateway gateway = enroll("gw-lock-" + unique());

		AuthorizeResponse response = authorize(gateway,
				request(identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID()));
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(response.getSessionToken()).isEmpty();
	}

	private AuthorizeResponse authorize(EnrolledGateway gateway, AuthorizeRequest request) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return AuthorizationGrpc.newBlockingStub(channel).authorize(request);
		} finally {
			shutdown(channel);
		}
	}

	private static AuthorizeRequest request(String identity, UUID nodeId, String principal, String sourceIp,
			UUID sessionId) {
		return AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
				.setRequestedPrincipal(principal).setSourceIp(sourceIp).setSessionId(sessionId.toString()).build();
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

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
