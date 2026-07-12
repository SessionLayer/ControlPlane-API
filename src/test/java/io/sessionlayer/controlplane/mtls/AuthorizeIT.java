package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.authz.ConnectAuthorizationService;
import io.sessionlayer.controlplane.authz.DecisionContextVerifier;
import io.sessionlayer.controlplane.ca.CaRotationService;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.CertificateRequest;
import io.sessionlayer.controlplane.ca.OpenSshCertificate;
import io.sessionlayer.controlplane.ca.SshCertSigner;
import io.sessionlayer.controlplane.ca.cert.CertType;
import io.sessionlayer.controlplane.ca.cert.CertificateParameters;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeHostKey;
import io.sessionlayer.controlplane.data.runtime.NodeHostKeyRepository;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.Capability;
import io.sessionlayer.controlplane.grpc.v1.ConnectorKind;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.DecisionContext;
import io.sessionlayer.controlplane.grpc.v1.HostVerification;
import io.sessionlayer.controlplane.grpc.v1.NodeConnection;
import io.sessionlayer.controlplane.grpc.v1.SignSessionCertificateResponse;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
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
	private NodeHostKeyRepository hostKeys;
	@Autowired
	private CaRotationService caRotation;
	@Autowired
	private CaSignerService caSigner;
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

	// ----- Part E: node connection + host-identity lookup (Design §9;
	// FR-CONN-1/2/5/7) -----

	@Test
	void allowReturnsAgentlessNodeConnectionWithHostCaVerificationMaterial() {
		String identity = "alice-" + unique();
		UUID nodeId = seedAgentlessNode("10.0.0.5"); // no port → dial gets :22 appended
		Node node = nodes.findById(nodeId).block();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec"));
		// A real host-CA-signed host cert whose principal is the node's enrollment
		// name.
		String hostCertLine = signHostCert(node.name());
		byte[] expectedCertBlob = Base64.getDecoder().decode(hostCertLine.trim().split("\\s+")[1]);
		seedHostCaAnchor(nodeId, hostCertLine);
		EnrolledGateway gateway = enroll("gw-conn-ca-" + unique());

		AuthorizeResponse response = authorize(gateway,
				request(identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID()));

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(response.hasNodeConnection()).isTrue();
		NodeConnection connection = response.getNodeConnection();
		assertThat(connection.getConnectorKind()).isEqualTo(ConnectorKind.CONNECTOR_KIND_AGENTLESS);
		assertThat(connection.getDialAddress()).isEqualTo("10.0.0.5:22");

		// host-CA path is the complete triple: trusted CA set (wire-decoded from the
		// same authorized-keys lines), the node name as expected principal, and the
		// enrollment host cert the Gateway verifies against them.
		HostVerification verification = connection.getHostVerification();
		List<String> expectedCaBlobs = caRotation.trustedCaKeys("host").block().stream()
				.map(line -> line.trim().split("\\s+")[1]).toList();
		List<String> actualCaBlobs = verification.getHostCaKeysList().stream()
				.map(bytes -> Base64.getEncoder().encodeToString(bytes.toByteArray())).toList();
		assertThat(actualCaBlobs).isNotEmpty().containsExactlyElementsOf(expectedCaBlobs);
		assertThat(verification.getExpectedHostPrincipalsList()).containsExactly(node.name());
		assertThat(verification.getPinnedHostKeysList()).isEmpty();
		assertThat(verification.getHostCertificatesList()).hasSize(1);
		assertThat(verification.getHostCertificates(0).toByteArray()).isEqualTo(expectedCertBlob);
	}

	@Test
	void allowReturnsAgentlessNodeConnectionWithPinnedHostKey() {
		String identity = "bob-" + unique();
		UUID nodeId = seedAgentlessNode("10.0.0.6:2222"); // explicit port → dial unchanged
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		byte[] pinnedBlob = seedPinnedHostKey(nodeId);
		EnrolledGateway gateway = enroll("gw-conn-pin-" + unique());

		AuthorizeResponse response = authorize(gateway,
				request(identity, nodeId, "deploy", "10.0.0.6", UUID.randomUUID()));

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		NodeConnection connection = response.getNodeConnection();
		assertThat(connection.getConnectorKind()).isEqualTo(ConnectorKind.CONNECTOR_KIND_AGENTLESS);
		assertThat(connection.getDialAddress()).isEqualTo("10.0.0.6:2222");

		HostVerification verification = connection.getHostVerification();
		assertThat(verification.getHostCaKeysList()).isEmpty();
		assertThat(verification.getExpectedHostPrincipalsList()).isEmpty();
		assertThat(verification.getHostCertificatesList()).isEmpty();
		assertThat(verification.getPinnedHostKeysList()).hasSize(1);
		assertThat(verification.getPinnedHostKeys(0).toByteArray()).isEqualTo(pinnedBlob);
	}

	@Test
	void allowOnAgentlessNodeWithNoHostKeysStillAllowsButEmptyVerificationAndWarns() {
		Logger logger = (Logger) LoggerFactory.getLogger(ConnectAuthorizationService.class);
		ListAppender<ILoggingEvent> appender = new ListAppender<>();
		appender.start();
		logger.addAppender(appender);
		try {
			String identity = "carol-" + unique();
			UUID nodeId = seedAgentlessNode("10.0.0.7");
			seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
			EnrolledGateway gateway = enroll("gw-conn-empty-" + unique());

			AuthorizeResponse response = authorize(gateway,
					request(identity, nodeId, "deploy", "10.0.0.7", UUID.randomUUID()));

			// A misconfigured node still ALLOWs (the Gateway fails closed on empty
			// verification, no TOFU) — the CP never synthesizes trust.
			assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
			NodeConnection connection = response.getNodeConnection();
			assertThat(connection.getConnectorKind()).isEqualTo(ConnectorKind.CONNECTOR_KIND_AGENTLESS);
			assertThat(connection.getDialAddress()).isEqualTo("10.0.0.7:22");
			HostVerification verification = connection.getHostVerification();
			assertThat(verification.getHostCaKeysList()).isEmpty();
			assertThat(verification.getPinnedHostKeysList()).isEmpty();
			assertThat(verification.getExpectedHostPrincipalsList()).isEmpty();
			assertThat(verification.getHostCertificatesList()).isEmpty();

			assertThat(appender.list).anySatisfy(event -> {
				assertThat(event.getLevel()).isEqualTo(Level.WARN);
				assertThat(event.getFormattedMessage()).contains("no host-verification material")
						.contains(nodeId.toString());
			});
		} finally {
			logger.detachAppender(appender);
		}
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

	private UUID seedAgentlessNode(String address) {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes
				.save(Node.create("node-" + unique(), null, labels, "agentless", "active", "healthy", null, address))
				.map(Node::id).block();
	}

	// A host_ca anchor: public_key holds the node's plain host key (public
	// material,
	// not read for this path); host_cert_ref holds the enrollment host CERTIFICATE
	// line the CP hands to the Gateway.
	private void seedHostCaAnchor(UUID nodeId, String hostCertLine) {
		byte[] blob = MtlsTestSupport
				.opensshPublicKeyBlob((ECPublicKey) MtlsTestSupport.generateEcKeyPair().getPublic());
		String hostKeyLine = "ecdsa-sha2-nistp256 " + Base64.getEncoder().encodeToString(blob);
		hostKeys.save(NodeHostKey.create(nodeId, "ecdsa-sha2-nistp256", hostKeyLine, "SHA256:ca-" + unique(),
				hostCertLine, "host_ca", Instant.now())).block();
	}

	// Sign a real host certificate off the provisioned host CA, principal = the
	// node
	// name (what §9.3 requires the Gateway to match).
	private String signHostCert(String principal) {
		SshCertSigner hostCa = caSigner.activeSigner("host").block();
		KeyPair hostKey = MtlsTestSupport.generateEcKeyPair();
		CertificateParameters parameters = new CertificateParameters(1L, CertType.HOST, "host-" + principal,
				List.of(principal), Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600), null, null);
		OpenSshCertificate cert = hostCa
				.signCertificate(new CertificateRequest((ECPublicKey) hostKey.getPublic(), parameters));
		return cert.certificateLine();
	}

	private byte[] seedPinnedHostKey(UUID nodeId) {
		byte[] blob = MtlsTestSupport
				.opensshPublicKeyBlob((ECPublicKey) MtlsTestSupport.generateEcKeyPair().getPublic());
		String line = "ecdsa-sha2-nistp256 " + Base64.getEncoder().encodeToString(blob) + " host@" + unique();
		hostKeys.save(NodeHostKey.create(nodeId, "ecdsa-sha2-nistp256", line, "SHA256:pin-" + unique(), null,
				"pinned_key", Instant.now())).block();
		return blob;
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
