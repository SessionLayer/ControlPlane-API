package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
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
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
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
import java.util.Map;
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
	@Autowired
	private AuditEventStore auditStore;
	@Autowired
	private AuditEventRepository auditEvents;

	// Part B (S20, FR-AUD-8/9): a real allow stamps EVERY searchable audit
	// dimension on the connect decision row, and the RBAC node-label scope filter —
	// inert while node_labels was null — now genuinely narrows.
	@Test
	void allowPopulatesEverySearchableAuditDimensionAndScopeFilters() {
		String identity = "audit-" + unique();
		UUID nodeId = seedProdNode(); // resolved labels {env:prod}
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell", "exec", "sftp"));
		EnrolledGateway gateway = enroll("gw-auditdim-" + unique());
		UUID sessionId = UUID.randomUUID();

		AuthorizeResponse response = authorize(gateway, request(identity, nodeId, "deploy", "10.0.0.5", sessionId));
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);

		AuditEvent connect = auditEvents.findBySessionId(sessionId).collectList().block().stream()
				.filter(e -> "authz.decision".equals(e.action()) && "success".equals(e.outcome())).findFirst()
				.orElseThrow();
		assertThat(connect.sourceIp()).isEqualTo("10.0.0.5");
		assertThat(connect.accessModel()).isEqualTo("standing");
		assertThat(connect.capabilities()).containsExactlyInAnyOrder("shell", "exec", "sftp");
		assertThat(connect.nodeLabels().get("env").stringValue()).isEqualTo("prod");
		// A standing chain begins at the session, so correlation_id == session id.
		assertThat(connect.correlationId()).isEqualTo(sessionId);

		// Each dimension filters back to this session's connect row (scoped by session
		// to isolate from sibling tests sharing the container).
		assertThat(searchIds(dim(sessionId, q -> q.sourceIp("10.0.0.5")))).contains(connect.id());
		assertThat(searchIds(dim(sessionId, q -> q.accessModel("standing")))).contains(connect.id());
		assertThat(searchIds(dim(sessionId, q -> q.capability("exec")))).contains(connect.id());
		assertThat(searchIds(dim(sessionId, q -> q.nodeLabels(Map.of("env", "prod"))))).contains(connect.id());
		// correlation_id (== session id here) is unique, so it returns exactly this
		// row.
		assertThat(searchIds(dim(null, q -> q.correlationId(sessionId)))).containsExactly(connect.id());

		// The label scope filter now engages on real data: an env=prod-scoped auditor
		// sees the row; an env=staging-scoped auditor does not (fail closed).
		assertThat(searchIds(dim(sessionId, q -> q.scopeGrants(List.of(labelScope("env", "prod"))))))
				.contains(connect.id());
		assertThat(searchIds(dim(sessionId, q -> q.scopeGrants(List.of(labelScope("env", "staging")))))).isEmpty();
	}

	// F-audit-ip-inet-abbrev-1: "16909060" passes InetAddress's inet_aton-style
	// parse but Postgres ::inet REJECTS it; the strict auditableIp validator drops
	// it to NULL so the best-effort DENY audit INSERT does not violate the
	// source_ip
	// CHECK and the decision-log row is NOT lost (FR-AUD-7).
	@Test
	void denyWithNonInetSourceIpStillWritesTheDecisionRow() {
		String identity = "denyip-" + unique();
		UUID nodeId = seedProdNode(); // no allow seeded → NO_MATCHING_ALLOW deny
		EnrolledGateway gateway = enroll("gw-denyip-" + unique());

		AuthorizeResponse response = authorize(gateway,
				request(identity, nodeId, "deploy", "16909060", UUID.randomUUID()));
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);

		AuditEvent deny = auditStore.search(new AuditQuery(null, identity, "authz.decision", "denied", null, null, null,
				null, null, null, null, Map.of(), null, List.of(), null, 50)).block().items().stream().findFirst()
				.orElseThrow();
		assertThat(deny.sourceIp()).isNull(); // dropped from the column (not a ::inet literal)
		assertThat(deny.detail().get("source_ip").stringValue()).isEqualTo("16909060"); // forensics retained in detail
	}

	private List<UUID> searchIds(AuditQuery query) {
		return auditStore.search(query).block().items().stream().map(AuditEvent::id).toList();
	}

	// A single-dimension query over an otherwise-empty filter set; a small mutator
	// sets the one column under test (keeps the 16-arg AuditQuery readable).
	private static AuditQuery dim(UUID sessionId, java.util.function.Consumer<DimBuilder> mutator) {
		DimBuilder b = new DimBuilder(sessionId);
		mutator.accept(b);
		return b.build();
	}

	private static final class DimBuilder {
		private final UUID sessionId;
		private String sourceIp;
		private String accessModel;
		private String capability;
		private Map<String, String> nodeLabels = Map.of();
		private UUID correlationId;
		private List<tools.jackson.databind.JsonNode> scopeGrants = List.of();

		private DimBuilder(UUID sessionId) {
			this.sessionId = sessionId;
		}

		DimBuilder sourceIp(String v) {
			this.sourceIp = v;
			return this;
		}

		DimBuilder accessModel(String v) {
			this.accessModel = v;
			return this;
		}

		DimBuilder capability(String v) {
			this.capability = v;
			return this;
		}

		DimBuilder nodeLabels(Map<String, String> v) {
			this.nodeLabels = v;
			return this;
		}

		DimBuilder correlationId(UUID v) {
			this.correlationId = v;
			return this;
		}

		DimBuilder scopeGrants(List<tools.jackson.databind.JsonNode> v) {
			this.scopeGrants = v;
			return this;
		}

		AuditQuery build() {
			return new AuditQuery(null, null, null, null, sessionId, null, sourceIp, null, null, capability,
					accessModel, nodeLabels, correlationId, scopeGrants, null, 50);
		}
	}

	private static tools.jackson.databind.JsonNode labelScope(String key, String value) {
		ObjectNode scope = JSON.objectNode();
		scope.set("node_labels", JSON.objectNode().put(key, value));
		return scope;
	}

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

	// S23 F-authorize-gateway-lock-1 (HIGH): a locked Gateway's still-valid client
	// cert MUST be refused on Authorize too, not only at Sign. Before the fix the
	// caller was used only for the audit name, so a locked Gateway stayed a full
	// RBAC oracle and could consume break-glass tokens / flip JIT grants / write
	// session rows with its un-expired cert (there is no CRL on the internal mTLS
	// CA
	// — the status lock IS the revocation, FR-BOOT-3/§8.4/FR-LOCK-2).
	@Test
	void aLockedCallerGatewayIsRefusedOnAuthorizeWithNoStateChange() {
		String identity = "alice-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell")); // otherwise-allowed
		EnrolledGateway gateway = enroll("gw-locked-caller-" + unique());
		// Lock the caller Gateway: the client cert stays cryptographically valid until
		// expiry, so the status flip is the only thing refusing it.
		db.sql("UPDATE runtime.gateway_identity SET status = 'locked' WHERE id = :id").bind("id", gateway.gatewayId())
				.fetch().rowsUpdated().block();
		UUID sessionId = UUID.randomUUID();

		AuthorizeResponse response = authorize(gateway, request(identity, nodeId, "deploy", "10.0.0.5", sessionId));

		// The same generic fail-closed shape as any denial: deny, no token, no context.
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(response.getSessionToken()).isEmpty();
		assertThat(response.hasContext()).isFalse();
		// And NOTHING was written despite the standing allow: no ssh_session decision
		// snapshot (nor any minted session/recording token — the empty token above).
		assertThat(sshSessions.findById(sessionId).block()).isNull();
	}

	@Test
	void signedContextCarriesIdentityGroupsAndNodeLabels() throws Exception {
		String identity = "alice-" + unique();
		UUID nodeId = seedProdNode(); // resolved labels {env:prod}
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-ctx-" + unique());
		UUID sessionId = UUID.randomUUID();

		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
				.addIdentityGroups("admins").addIdentityGroups("oncall").setRequestedPrincipal("deploy")
				.setSourceIp("10.0.0.5").setSessionId(sessionId.toString()).build();
		AuthorizeResponse response = authorize(gateway, request);

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		DecisionContext parsed = DecisionContext.parseFrom(response.getSignedContext());
		// S10: identity/groups/node-labels are SIGNED so the Gateway matches locks
		// against trusted data (never data it was merely told).
		assertThat(parsed.getIdentity()).isEqualTo(identity);
		assertThat(parsed.getIdentityGroupsList()).containsExactly("admins", "oncall");
		assertThat(parsed.getNodeLabelsList()).containsExactly("env=prod");
		// The signature still verifies over the now-larger signed bytes (round-trip).
		assertThat(DecisionContextVerifier.verify(caCertificate(), response.getSignerCertificate().toByteArray(),
				response.getSignedContext().toByteArray(), response.getSignature().toByteArray())).isTrue();
	}

	// ----- S16 Part A: name→id resolution (server-authoritative, §2.6/§11) -----

	@Test
	void resolvesTheNodeByNameAndAllows() throws Exception {
		String identity = "alice-" + unique();
		UUID nodeId = seedProdNode();
		Node node = nodes.findById(nodeId).block();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-byname-" + unique());
		UUID sessionId = UUID.randomUUID();

		AuthorizeResponse response = authorize(gateway,
				requestByName(identity, node.name(), "deploy", "10.0.0.5", sessionId));

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		DecisionContext parsed = DecisionContext.parseFrom(response.getSignedContext());
		assertThat(parsed.getNodeId()).isEqualTo(nodeId.toString());
		assertThat(parsed.getNodeName()).isEqualTo(node.name());
	}

	@Test
	void anUnknownNodeNameDeniesGenericallyWithoutDisclosure() {
		String identity = "alice-" + unique();
		EnrolledGateway gateway = enroll("gw-unkname-" + unique());

		AuthorizeResponse response = authorize(gateway,
				requestByName(identity, "no-such-node-" + unique(), "deploy", "10.0.0.5", UUID.randomUUID()));

		// The SAME generic deny as any no-match — no existence disclosure (§7.1).
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(response.getSessionToken()).isEmpty();
		assertThat(response.hasContext()).isFalse();
	}

	@Test
	void theNodeNameWinsOverAConflictingNodeId() throws Exception {
		String identity = "alice-" + unique();
		UUID namedNodeId = seedProdNode();
		UUID otherNodeId = seedProdNode(); // a different, also-prod node
		Node named = nodes.findById(namedNodeId).block();
		// The allow matches identity + env=prod; BOTH nodes are prod, so the outcome
		// hinges purely on which node is resolved — the name must win over the id.
		seedAllow(identity, namedNodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-namewins-" + unique());
		UUID sessionId = UUID.randomUUID();

		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).setNodeName(named.name())
				.setNodeId(otherNodeId.toString()).setRequestedPrincipal("deploy").setSourceIp("10.0.0.5")
				.setSessionId(sessionId.toString()).build();
		AuthorizeResponse response = authorize(gateway, request);

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		DecisionContext parsed = DecisionContext.parseFrom(response.getSignedContext());
		// The resolved node is the NAMED one — the smuggled id was ignored.
		assertThat(parsed.getNodeId()).isEqualTo(namedNodeId.toString());
		assertThat(parsed.getNodeId()).isNotEqualTo(otherNodeId.toString());
	}

	// ----- S16 Part D: unavailable nodes are excluded from targeting (FR-NODE-3)
	// -----

	@Test
	void aQuarantinedNodeDeniesGenerically() {
		assertUnavailableNodeDenies("quarantined");
	}

	@Test
	void aRemovedNodeDeniesGenerically() {
		assertUnavailableNodeDenies("removed");
	}

	@Test
	void aPendingNodeDeniesGenerically() {
		assertUnavailableNodeDenies("pending");
	}

	private void assertUnavailableNodeDenies(String status) {
		String identity = "alice-" + unique();
		UUID nodeId = seedNodeWithStatus(status);
		// A standing allow exists — only the node's status suppresses it (the status
		// gate precedes rule evaluation), so this proves the exclusion, not a missing
		// rule.
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-" + status + "-" + unique());

		AuthorizeResponse response = authorize(gateway,
				request(identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID()));

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_DENY);
		assertThat(response.getSessionToken()).isEmpty();
		assertThat(response.hasContext()).isFalse();
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
		// name; store its authorized-keys line and assert the CP hands over the exact
		// cert wire blob decoded from that line (not a re-encode of the same token).
		OpenSshCertificate hostCert = signHostCert(node.name());
		seedHostCaAnchor(nodeId, hostCert.certificateLine());
		EnrolledGateway gateway = enroll("gw-conn-ca-" + unique());

		AuthorizeResponse response = authorize(gateway,
				request(identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID()));

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(response.hasNodeConnection()).isTrue();
		NodeConnection connection = response.getNodeConnection();
		assertThat(connection.getConnectorKind()).isEqualTo(ConnectorKind.CONNECTOR_KIND_AGENTLESS);
		assertThat(connection.getDialAddress()).isEqualTo("10.0.0.5:22");
		// The node name is carried for EVERY connector kind, not just OUTBOUND_AGENT.
		assertThat(connection.getNodeName()).isEqualTo(node.name());

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
		assertThat(verification.getHostCertificates(0).toByteArray()).isEqualTo(hostCert.blob());
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

	@Test
	void allowOnOutboundAgentNodeReturnsTheNodeNameJoinKey() {
		String identity = "dave-" + unique();
		UUID nodeId = seedProdNode(); // connector_kind = agent
		Node node = nodes.findById(nodeId).block();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-conn-agent-" + unique());

		AuthorizeResponse response = authorize(gateway,
				request(identity, nodeId, "deploy", "10.0.0.8", UUID.randomUUID()));

		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(response.hasNodeConnection()).isTrue();
		NodeConnection connection = response.getNodeConnection();
		assertThat(connection.getConnectorKind()).isEqualTo(ConnectorKind.CONNECTOR_KIND_OUTBOUND_AGENT);

		// S14: the join key between this session and the agent that owns the node. The
		// Gateway matches it against the dNSName SAN of the agent's mTLS certificate —
		// which the CP itself stamped from node.name — to find the agent's control
		// channel. Empty here would make the Gateway fail closed to "node offline".
		assertThat(connection.getNodeName()).isNotBlank().isEqualTo(node.name());

		// An outbound agent dials out; there is nothing for the Gateway to dial.
		assertThat(connection.getDialAddress()).isEmpty();
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

	private static AuthorizeRequest requestByName(String identity, String nodeName, String principal, String sourceIp,
			UUID sessionId) {
		return AuthorizeRequest.newBuilder().setIdentity(identity).setNodeName(nodeName)
				.setRequestedPrincipal(principal).setSourceIp(sourceIp).setSessionId(sessionId.toString()).build();
	}

	private UUID seedNodeWithStatus(String status) {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", status, "unknown", null, null))
				.map(Node::id).block();
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
	private OpenSshCertificate signHostCert(String principal) {
		SshCertSigner hostCa = caSigner.activeSigner("host").block();
		KeyPair hostKey = MtlsTestSupport.generateEcKeyPair();
		CertificateParameters parameters = new CertificateParameters(1L, CertType.HOST, "host-" + principal,
				List.of(principal), Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600), null, null);
		return hostCa.signCertificate(new CertificateRequest((ECPublicKey) hostKey.getPublic(), parameters));
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
