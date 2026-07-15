package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.agent.AgentJoinTokenService;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.grpc.v1.AgentIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.EnrollAgentRequest;
import io.sessionlayer.controlplane.grpc.v1.EnrollAgentResponse;
import io.sessionlayer.controlplane.grpc.v1.MtlsJoinProof;
import io.sessionlayer.controlplane.grpc.v1.OidcJoinProof;
import io.sessionlayer.controlplane.grpc.v1.RenewAgentIdentityRequest;
import io.sessionlayer.controlplane.grpc.v1.RenewAgentIdentityResponse;
import io.sessionlayer.controlplane.grpc.v1.TokenJoinProof;
import io.sessionlayer.controlplane.support.StubIdp;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Session Twelve — Agent join &amp; renewable-identity lifecycle over the real
 * mTLS gRPC plane (FR-JOIN-1/3/4/6, §8). Enrollment via each in-scope
 * JoinMethod (token / delegated-OIDC / operator-mTLS) issues a generation-0
 * identity bound to a distinct per-node credential; renewal rotates the cert +
 * increments the generation; a generation mismatch auto-locks the identity +
 * node (clone detection, §8.2); a Lock covering the node refuses enroll; a
 * consumed token is single-use.
 */
class AgentJoinLifecycleIT extends AbstractMtlsIT {

	private static final String POP_PREFIX = "sessionlayer-mtls-join-pop-v1:";
	private static final String OIDC_AUDIENCE = "sessionlayer-agents";

	private static final StubIdp IDP;
	private static final KeyPair OPERATOR_CA_KEY = MtlsTestSupport.generateEcKeyPair();
	private static final X509Certificate OPERATOR_CA;

	static {
		try {
			IDP = new StubIdp("unused-client-id");
		} catch (Exception e) {
			throw new IllegalStateException("failed to start the workload StubIdp", e);
		}
		Instant nb = Instant.now().minus(Duration.ofHours(1));
		Instant na = Instant.now().plus(Duration.ofDays(1));
		OPERATOR_CA = X509Certificates.selfSignCa("operator-ca", OPERATOR_CA_KEY.getPublic(),
				OPERATOR_CA_KEY.getPrivate(), BigInteger.valueOf(1), nb, na);
	}

	@DynamicPropertySource
	static void agentJoinProperties(DynamicPropertyRegistry registry) {
		registry.add("sessionlayer.agent-join.oidc.enabled", () -> "true");
		registry.add("sessionlayer.agent-join.oidc.issuer", IDP::issuer);
		registry.add("sessionlayer.agent-join.oidc.jwks-uri", () -> IDP.issuer() + "/jwks");
		registry.add("sessionlayer.agent-join.oidc.audience", () -> OIDC_AUDIENCE);
		registry.add("sessionlayer.agent-join.oidc.node-claim", () -> "node_name");
		registry.add("sessionlayer.agent-join.mtls.enabled", () -> "true");
		registry.add("sessionlayer.agent-join.mtls.operator-ca-pem", () -> pem(OPERATOR_CA));
	}

	@Autowired
	private AgentJoinTokenService joinTokens;
	@Autowired
	private AgentIdentityRepository agentIdentities;
	@Autowired
	private NodeRepository nodes;
	@Autowired
	private AccessLockRepository accessLocks;

	private record EnrolledAgent(UUID agentId, UUID nodeId, KeyPair keyPair, X509Certificate certificate,
			long generation) {
	}

	@Test
	void tokenEnrollIssuesGenerationZeroAndRegistersNode() throws Exception {
		EnrolledAgent agent = enrollToken("node-token");
		assertThat(agent.generation()).isZero();

		AgentIdentity identity = agentIdentities.findById(agent.agentId()).block();
		assertThat(identity.status()).isEqualTo("active");
		assertThat(identity.joinMethod()).isEqualTo("token");
		assertThat(identity.nodeId()).isEqualTo(agent.nodeId());
		assertThat(identity.fingerprint()).isNotBlank();

		Node node = nodes.findById(agent.nodeId()).block();
		assertThat(node.name()).isEqualTo("node-token");
		assertThat(node.connectorKind()).isEqualTo("agent");

		// The issued cert carries the agent identity SAN the interceptor resolves.
		assertThat(uriSans(agent.certificate())).contains(AgentIdentityUri.of(agent.agentId()));
	}

	@Test
	void aConsumedTokenIsSingleUse() {
		String raw = joinTokens.mint("node-single", "test-admin", Duration.ofMinutes(10)).block().rawToken();
		submit(tokenRequest("node-single", raw)); // consumes

		// Replaying the consumed token (even for a different node) is rejected.
		StatusRuntimeException replay = catchThrowableOfType(StatusRuntimeException.class,
				() -> submit(tokenRequest("node-single-2", raw)));
		assertThat(replay.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void oidcEnrollIssuesGenerationZero() {
		EnrolledAgent agent = enrollOidc("node-oidc", "node-oidc");
		assertThat(agent.generation()).isZero();
		assertThat(agentIdentities.findById(agent.agentId()).block().joinMethod()).isEqualTo("oidc");
	}

	@Test
	void oidcNodeClaimMismatchIsRefused() {
		// The verified node-binding claim ("other-node") must equal the requested node.
		StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
				() -> enrollOidc("node-oidc-mismatch", "other-node"));
		assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	@Test
	void mtlsEnrollIssuesGenerationZero() throws Exception {
		EnrolledAgent agent = enrollMtls("node-mtls");
		assertThat(agent.generation()).isZero();
		assertThat(agentIdentities.findById(agent.agentId()).block().joinMethod()).isEqualTo("mtls");
	}

	@Test
	void renewRotatesCertificateAndIncrementsGeneration() {
		EnrolledAgent agent = enrollToken("node-renew");
		String beforeFingerprint = agentIdentities.findById(agent.agentId()).block().fingerprint();

		RenewAgentIdentityResponse renewed = renew(agent, "node-renew", 0);
		assertThat(renewed.getGeneration()).isEqualTo(1);

		AgentIdentity after = agentIdentities.findById(agent.agentId()).block();
		assertThat(after.generation()).isEqualTo(1);
		assertThat(after.fingerprint()).isNotEqualTo(beforeFingerprint);
		assertThat(after.prevFingerprint()).isEqualTo(beforeFingerprint); // renew-ahead overlap
	}

	@Test
	void generationMismatchAutoLocksNodeAndAlerts() {
		EnrolledAgent agent = enrollToken("node-clone");

		// Declare a generation the store never issued — the clone-detection primitive.
		StatusRuntimeException mismatch = catchThrowableOfType(StatusRuntimeException.class,
				() -> renew(agent, "node-clone", 7));
		assertThat(mismatch.getStatus().getCode()).isEqualTo(Status.Code.FAILED_PRECONDITION);

		AgentIdentity locked = agentIdentities.findById(agent.agentId()).block();
		assertThat(locked.status()).isEqualTo("locked");
		assertThat(locked.statusChangedBy()).isEqualTo("system:clone-detection");

		AccessLock cloneLock = accessLocks.findAll().toStream().filter(
				lock -> coversNode(lock, agent.nodeId()) && "strict".equals(lock.mode()) && lock.expiresAt() == null)
				.findFirst().orElseThrow();

		// The clone lock must reach the cloned agent as a PEER, not only as a node. An
		// agent's cert carries its node NAME (dNSName SAN) and its agent id (URI SAN),
		// never the node UUID — so a node_ids-only selector cannot match an agent
		// control channel and the Gateway would not refuse the clone at registration or
		// dial-back (S14).
		assertThat(selectorValues(cloneLock, "node_ids")).containsExactly(agent.nodeId().toString());
		assertThat(selectorValues(cloneLock, "identities")).containsExactly(agent.agentId().toString());

		Long alerts = db
				.sql("SELECT count(*) FROM runtime.audit_event WHERE action = 'agent.identity.clone_detected' "
						+ "AND subject = :agent")
				.bind("agent", agent.agentId().toString()).map(row -> row.get(0, Long.class)).one().block();
		assertThat(alerts).isGreaterThanOrEqualTo(1L);

		// The locked identity is refused even for a correct-generation renewal (no
		// auto-clear).
		StatusRuntimeException afterLock = catchThrowableOfType(StatusRuntimeException.class,
				() -> renew(agent, "node-clone", 0));
		assertThat(afterLock.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
	}

	@Test
	void aLockCoveringTheNodeRefusesEnroll() {
		Node node = nodes.save(Node.create("node-locked", null, JsonNodeFactory.instance.objectNode(), "agent",
				"active", "unknown", null, null)).block();
		ObjectNode selector = JsonNodeFactory.instance.objectNode();
		selector.putArray("node_ids").add(node.id().toString());
		accessLocks.save(AccessLock.create(selector, "strict", null, null, "incident", "test-admin")).block();

		StatusRuntimeException refused = catchThrowableOfType(StatusRuntimeException.class,
				() -> submit(tokenRequest("node-locked", mintToken("node-locked"))));
		assertThat(refused.getStatus().getCode()).isEqualTo(Status.Code.PERMISSION_DENIED);
	}

	@Test
	void perNodeCredentialsAreDistinct() {
		EnrolledAgent a = enrollToken("node-dist-a");
		EnrolledAgent b = enrollToken("node-dist-b");

		assertThat(a.agentId()).isNotEqualTo(b.agentId());
		assertThat(a.nodeId()).isNotEqualTo(b.nodeId());
		assertThat(agentIdentities.findById(a.agentId()).block().fingerprint())
				.isNotEqualTo(agentIdentities.findById(b.agentId()).block().fingerprint());
	}

	// ---- helpers ---------------------------------------------------------------

	private EnrolledAgent enrollToken(String nodeName) {
		KeyPair keyPair = MtlsTestSupport.generateEcKeyPair();
		byte[] csr = MtlsTestSupport.csr(keyPair, nodeName);
		EnrollAgentResponse response = submit(
				EnrollAgentRequest.newBuilder().setNodeName(nodeName).setPkcs10Csr(ByteString.copyFrom(csr))
						.setToken(TokenJoinProof.newBuilder().setJoinToken(mintToken(nodeName))).build());
		return toEnrolled(response, keyPair);
	}

	private EnrolledAgent enrollOidc(String nodeName, String claimedNode) {
		String token = IDP.workloadToken(OIDC_AUDIENCE, "node_name", claimedNode, Instant.now().plusSeconds(300));
		KeyPair keyPair = MtlsTestSupport.generateEcKeyPair();
		byte[] csr = MtlsTestSupport.csr(keyPair, nodeName);
		EnrollAgentResponse response = submit(
				EnrollAgentRequest.newBuilder().setNodeName(nodeName).setPkcs10Csr(ByteString.copyFrom(csr))
						.setOidc(OidcJoinProof.newBuilder().setWorkloadToken(token)).build());
		return toEnrolled(response, keyPair);
	}

	private EnrolledAgent enrollMtls(String nodeName) throws Exception {
		KeyPair keyPair = MtlsTestSupport.generateEcKeyPair();
		byte[] csr = MtlsTestSupport.csr(keyPair, nodeName);
		KeyPair operatorLeafKey = MtlsTestSupport.generateEcKeyPair();
		X509Certificate operatorLeaf = X509Certificates.issueLeaf(OPERATOR_CA, OPERATOR_CA_KEY.getPrivate(),
				new LeafCertificateSpec(operatorLeafKey.getPublic(), nodeName, List.of(nodeName), List.of(),
						LeafPurpose.CLIENT, BigInteger.valueOf(System.nanoTime()), Instant.now().minusSeconds(60),
						Instant.now().plusSeconds(3600)));
		byte[] pop = signPop(operatorLeafKey, csr);
		EnrollAgentResponse response = submit(
				EnrollAgentRequest.newBuilder().setNodeName(nodeName).setPkcs10Csr(ByteString.copyFrom(csr))
						.setMtls(MtlsJoinProof.newBuilder()
								.setOperatorCertificate(ByteString.copyFrom(operatorLeaf.getEncoded()))
								.setPopSignature(ByteString.copyFrom(pop)))
						.build());
		return toEnrolled(response, keyPair);
	}

	private String mintToken(String nodeName) {
		return joinTokens.mint(nodeName, "test-admin", Duration.ofMinutes(10)).block().rawToken();
	}

	private EnrollAgentRequest tokenRequest(String nodeName, String rawToken) {
		byte[] csr = MtlsTestSupport.csr(MtlsTestSupport.generateEcKeyPair(), nodeName);
		return EnrollAgentRequest.newBuilder().setNodeName(nodeName).setPkcs10Csr(ByteString.copyFrom(csr))
				.setToken(TokenJoinProof.newBuilder().setJoinToken(rawToken)).build();
	}

	private EnrollAgentResponse submit(EnrollAgentRequest request) {
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(),
				MtlsTestSupport.clientSslContext(caCertificate(), null, null));
		try {
			return AgentIdentityGrpc.newBlockingStub(channel).enrollAgent(request);
		} finally {
			shutdown(channel);
		}
	}

	private RenewAgentIdentityResponse renew(EnrolledAgent agent, String nodeName, long currentGeneration) {
		KeyPair newKey = MtlsTestSupport.generateEcKeyPair();
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), agent.certificate(),
				agent.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return AgentIdentityGrpc.newBlockingStub(channel)
					.renewAgentIdentity(RenewAgentIdentityRequest.newBuilder()
							.setPkcs10Csr(ByteString.copyFrom(MtlsTestSupport.csr(newKey, nodeName)))
							.setCurrentGeneration(currentGeneration).build());
		} finally {
			shutdown(channel);
		}
	}

	private EnrolledAgent toEnrolled(EnrollAgentResponse response, KeyPair keyPair) {
		return new EnrolledAgent(UUID.fromString(response.getAgentId()), UUID.fromString(response.getNodeId()), keyPair,
				X509Certificates.parse(response.getCertificate().toByteArray()), response.getGeneration());
	}

	private static byte[] signPop(KeyPair operatorLeafKey, byte[] csr) throws Exception {
		byte[] prefix = POP_PREFIX.getBytes(StandardCharsets.US_ASCII);
		byte[] message = new byte[prefix.length + csr.length];
		System.arraycopy(prefix, 0, message, 0, prefix.length);
		System.arraycopy(csr, 0, message, prefix.length, csr.length);
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initSign(operatorLeafKey.getPrivate());
		signature.update(message);
		return signature.sign();
	}

	private static List<String> selectorValues(AccessLock lock, String facet) {
		var values = lock.targetSelector().get(facet);
		if (values == null || !values.isArray()) {
			return List.of();
		}
		List<String> out = new ArrayList<>();
		values.forEach(element -> out.add(element.stringValue()));
		return out;
	}

	private static boolean coversNode(AccessLock lock, UUID nodeId) {
		var nodeIds = lock.targetSelector().get("node_ids");
		if (nodeIds == null || !nodeIds.isArray()) {
			return false;
		}
		for (var element : nodeIds) {
			if (nodeId.toString().equals(element.stringValue())) {
				return true;
			}
		}
		return false;
	}

	private static List<String> uriSans(X509Certificate certificate) throws Exception {
		return certificate.getSubjectAlternativeNames().stream().filter(san -> (Integer) san.get(0) == 6)
				.map(san -> (String) san.get(1)).toList();
	}

	private static String pem(X509Certificate cert) {
		try {
			return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
					.encodeToString(cert.getEncoded()) + "\n-----END CERTIFICATE-----\n";
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}
}
