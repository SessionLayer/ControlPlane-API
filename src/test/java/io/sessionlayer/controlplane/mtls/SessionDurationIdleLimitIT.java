package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.breakglass.BreakglassCredentialService;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicy;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.BreakglassResolution;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.DecisionContext;
import io.sessionlayer.controlplane.grpc.v1.OuterLegAuthGrpc;
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassKeyRequest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Session 25 Parts B + C (CP side) — the two previously-dead
 * {@code session_limit_policy} knobs are enforced at Authorize:
 * {@code max_session_seconds} is folded into the decision's
 * {@code grant_expiry} (most restrictive policy wins; the
 * {@code operator_settings} default is the fallback) and
 * {@code idle_timeout_seconds} rides SIGNED in the decision context (field 17,
 * emitted only when resolved so a no-policy decision's signed bytes stay
 * byte-identical to the pre-S25 encoding — N-1). Break-glass is exempt from
 * both.
 */
class SessionDurationIdleLimitIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final String SOURCE_IP = "203.0.113.11";

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private SessionLimitPolicyRepository sessionLimitPolicies;
	@Autowired
	private BreakglassCredentialService breakglassCredentials;

	// Policies + the operator_settings singleton are shared decision-path config;
	// leave both clean for the other suites (S17 lesson).
	@AfterEach
	void resetLimitConfig() {
		sessionLimitPolicies.deleteAll().block();
		db.sql("UPDATE config.operator_settings SET default_max_session_seconds = NULL, "
				+ "default_idle_timeout_seconds = NULL WHERE singleton = true").fetch().rowsUpdated().block();
	}

	@Test
	void theMostRestrictivePolicyMaxDurationCapsGrantExpiry() {
		String identity = "dur-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, null, 300, null);
		seedPolicy(identity, null, 120, null); // most restrictive wins

		AuthorizeResponse response = authorize(enroll("gw-dur-" + unique()), identity, nodeId, "deploy");
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);

		long now = Instant.now().getEpochSecond();
		long expiry = response.getContext().getGrantExpiryEpochSeconds();
		assertThat(expiry - now).isBetween(90L, 130L); // 120s policy, not the 3600s grant TTL

		// The capped expiry IS the signed value and the ssh_session snapshot.
		assertThat(parseSigned(response).getGrantExpiryEpochSeconds()).isEqualTo(expiry);
		Instant stored = sshSessions.findByIdentity(identity).blockFirst().grantExpiry();
		assertThat(stored.getEpochSecond()).isEqualTo(expiry);
	}

	@Test
	void theOperatorDefaultDurationAppliesWhenNoPolicyMatches() {
		String identity = "dur-default-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		db.sql("UPDATE config.operator_settings SET default_max_session_seconds = 180 WHERE singleton = true").fetch()
				.rowsUpdated().block();

		AuthorizeResponse response = authorize(enroll("gw-durdef-" + unique()), identity, nodeId, "deploy");
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		long delta = response.getContext().getGrantExpiryEpochSeconds() - Instant.now().getEpochSecond();
		assertThat(delta).isBetween(150L, 190L);
	}

	@Test
	void aResolvedIdleTimeoutRidesSignedInTheContext() {
		String identity = "idle-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		seedPolicy(identity, null, null, 300);

		AuthorizeResponse response = authorize(enroll("gw-idle-" + unique()), identity, nodeId, "deploy");
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(response.getContext().getIdleTimeoutSeconds()).isEqualTo(300L);
		// In the SIGNED bytes, not just the convenience copy (not client-forgeable).
		assertThat(parseSigned(response).getIdleTimeoutSeconds()).isEqualTo(300L);
		// The idle-only policy leaves the duration at the grant TTL (3600s rule).
		long delta = response.getContext().getGrantExpiryEpochSeconds() - Instant.now().getEpochSecond();
		assertThat(delta).isBetween(3500L, 3650L);
	}

	@Test
	void theOperatorDefaultIdleAppliesWhenNoPolicyMatches() {
		String identity = "idle-default-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));
		db.sql("UPDATE config.operator_settings SET default_idle_timeout_seconds = 240 WHERE singleton = true").fetch()
				.rowsUpdated().block();

		AuthorizeResponse response = authorize(enroll("gw-idledef-" + unique()), identity, nodeId, "deploy");
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(parseSigned(response).getIdleTimeoutSeconds()).isEqualTo(240L);
	}

	@Test
	void noIdlePolicyKeepsTheSignedBytesByteIdenticalToPreS25() {
		String identity = "n1-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("deploy"), List.of("shell"));

		AuthorizeResponse response = authorize(enroll("gw-n1-" + unique()), identity, nodeId, "deploy");
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);

		DecisionContext signed = parseSigned(response);
		assertThat(signed.getIdleTimeoutSeconds()).isZero();
		// Field 17 is truly ABSENT from the signed bytes (not encoded-as-zero):
		// clearing it changes nothing, so an N-1 Gateway verifies the same bytes it
		// always did.
		assertThat(signed.toBuilder().clearIdleTimeoutSeconds().build().toByteArray())
				.isEqualTo(response.getSignedContext().toByteArray());
	}

	// Break-glass keeps its own TTL (1h default) and carries no per-identity
	// idle even when a matching policy sets tight values — the emergency path is
	// never throttled by per-identity policy (consistent with the S24 cap
	// exemption).
	@Test
	void breakGlassIsExemptFromDurationAndIdlePolicies() throws Exception {
		String identity = "bg-dur-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, nodeId, List.of("root"), List.of("shell"));
		seedPolicy(identity, null, 60, 60);
		byte[] sk = skBlob((byte) 0x66);
		breakglassCredentials.register(sk, identity, List.of("root"), null, null, "admin").block();
		EnrolledGateway gateway = enroll("gw-bgdur-" + unique());

		BreakglassResolution resolution = resolveKey(gateway, sk, nodeId);
		assertThat(resolution.getBreakglassToken()).isNotBlank();
		AuthorizeResponse response = authorizeBreakglass(gateway, identity, nodeId, resolution.getBreakglassToken());
		assertThat(response.getDecision()).isEqualTo(Decision.DECISION_ALLOW);

		long delta = response.getContext().getGrantExpiryEpochSeconds() - Instant.now().getEpochSecond();
		assertThat(delta).isGreaterThan(3000L); // the break-glass TTL, not the 60s policy
		DecisionContext signed = parseSigned(response);
		assertThat(signed.getIdleTimeoutSeconds()).isZero();
		assertThat(signed.toBuilder().clearIdleTimeoutSeconds().build().toByteArray())
				.isEqualTo(response.getSignedContext().toByteArray());
	}

	// ----------------------- helpers -----------------------

	private static DecisionContext parseSigned(AuthorizeResponse response) {
		try {
			return DecisionContext.parseFrom(response.getSignedContext());
		} catch (com.google.protobuf.InvalidProtocolBufferException e) {
			throw new AssertionError("unparseable signed context", e);
		}
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

	private void seedPolicy(String identity, Integer maxConcurrent, Integer maxSeconds, Integer idleSeconds) {
		ObjectNode selector = JSON.objectNode();
		selector.set("identities", JSON.arrayNode().add(identity));
		sessionLimitPolicies.save(
				SessionLimitPolicy.create("limit-" + unique(), selector, maxConcurrent, maxSeconds, idleSeconds, "api"))
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
