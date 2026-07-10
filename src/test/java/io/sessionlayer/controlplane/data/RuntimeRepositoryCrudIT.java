package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivationRepository;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.JoinToken;
import io.sessionlayer.controlplane.data.runtime.JoinTokenRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.Otp;
import io.sessionlayer.controlplane.data.runtime.OtpRepository;
import io.sessionlayer.controlplane.data.runtime.Presence;
import io.sessionlayer.controlplane.data.runtime.PresenceRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.ObjectMapper;

/**
 * CRUD round-trips (§8.3) for the RUNTIME repositories, plus the
 * runtime-specific invariants that are happy-path here (negative cases live in
 * {@link ConstraintsIT}): the 1:1 {@code recording_ref}, presence routing
 * lookup, and the decision-snapshot columns on {@code ssh_session} (§6).
 */
class RuntimeRepositoryCrudIT extends AbstractDataIT {

	@Autowired
	private NodeRepository nodes;

	@Autowired
	private PresenceRepository presences;

	@Autowired
	private AgentIdentityRepository agentIdentities;

	@Autowired
	private GatewayIdentityRepository gatewayIdentities;

	@Autowired
	private JoinTokenRepository joinTokens;

	@Autowired
	private SshSessionRepository sessions;

	@Autowired
	private RecordingRefRepository recordings;

	@Autowired
	private AccessLockRepository locks;

	@Autowired
	private BreakglassActivationRepository breakglass;

	@Autowired
	private OtpRepository otps;

	@Autowired
	private ObjectMapper objectMapper;

	private Node newNode(String name) {
		return nodes.save(Node.create(name, "policy-x", objectMapper.readTree("{\"env\":\"prod\"}"), "agent", "active",
				"healthy", "gw-1", "10.0.0.5:22")).block();
	}

	@Test
	void nodeCrudAndFinders() {
		var node = newNode("node-crud");
		assertThat(node).isNotNull();
		assertThat(nodes.findByName("node-crud").block().id()).isEqualTo(node.id());
		assertThat(nodes.findByStatus("active").collectList().block()).isNotEmpty();
		assertThat(node.resolvedLabels().get("env").asString()).isEqualTo("prod");
	}

	@Test
	void presenceKeyedByNodeAndRoutingLookup() {
		var node = newNode("node-presence");
		var presence = presences
				.save(Presence.create(node.id(), "gw-a", "10.1.1.1:7000", 42L, UUID.randomUUID(), Instant.now()))
				.block();
		assertThat(presence).isNotNull();
		assertThat(presence.nodeId()).isEqualTo(node.id());
		assertThat(presences.findByOwningGateway("gw-a").collectList().block()).hasSize(1);
		// "who owns node X" is the PK lookup
		assertThat(presences.findById(node.id()).block().nonce()).isEqualTo(42L);
	}

	@Test
	void agentAndGatewayIdentities() {
		var node = newNode("node-id");
		var agent = agentIdentities.save(AgentIdentity.create(node.id(), "spiffe://agent", "SHA256:aa", 0, "token",
				"active", Instant.now(), Instant.now().plus(24, ChronoUnit.HOURS))).block();
		assertThat(agent).isNotNull();
		assertThat(agentIdentities.findByNodeIdAndStatus(node.id(), "active").block().id()).isEqualTo(agent.id());

		var gw = gatewayIdentities.save(GatewayIdentity.create("gw-west-1", "spiffe://gw", "SHA256:bb", 0, "mtls",
				"active", Instant.now(), null)).block();
		assertThat(gatewayIdentities.findByName("gw-west-1").block().id()).isEqualTo(gw.id());
	}

	@Test
	void joinTokenStoresHashOnly() {
		var node = newNode("node-join");
		var scope = objectMapper.readTree("{\"labels\":{\"env\":\"prod\"}}");
		var token = joinTokens.save(JoinToken.create("hash-abc", scope, "token", node.id(), true,
				Instant.now().plus(10, ChronoUnit.MINUTES), "admin")).block();
		assertThat(token).isNotNull();
		assertThat(joinTokens.findByTokenHash("hash-abc").block().id()).isEqualTo(token.id());
	}

	@Test
	void sessionCarriesDecisionSnapshotAndRecordingIsOneToOne() {
		var node = newNode("node-session");
		var gw = gatewayIdentities.save(
				GatewayIdentity.create("gw-session", "spiffe://gw2", null, 0, "mtls", "active", Instant.now(), null))
				.block();
		// matchedRuleId is a plain uuid with NO dp_rule row: the snapshot has no FK,
		// proving
		// history survives config GC (§6). policyEpoch/capabilities/principal are
		// snapshots.
		UUID phantomRuleId = Uuids.v7();
		var session = sessions.save(SshSession.create("alice@corp", node.id(), node.name(), "deploy", gw.id(),
				gw.name(), "jit", List.of("shell", "exec"), phantomRuleId, null, 7L, Instant.now())).block();
		assertThat(session).isNotNull();
		assertThat(session.matchedRuleId()).isEqualTo(phantomRuleId);
		assertThat(session.policyEpoch()).isEqualTo(7L);
		assertThat(sessions.findByIdentity("alice@corp").collectList().block()).hasSize(1);

		var rec = recordings.save(RecordingRef.create(session.id(), "s3://bucket/rec1", "kms://cust-key", "chainhead0",
				"compliance", 1024L)).block();
		assertThat(rec).isNotNull();
		assertThat(recordings.findBySessionId(session.id()).block().objectKey()).isEqualTo("s3://bucket/rec1");
	}

	@Test
	void accessLockCrud() {
		var target = objectMapper.readTree("{\"identity\":\"mallory@corp\"}");
		var lock = locks.save(AccessLock.create(target, "strict", 3600, Instant.now().plus(1, ChronoUnit.HOURS),
				"incident-42", "admin")).block();
		assertThat(lock).isNotNull();
		assertThat(locks.findByMode("strict").collectList().block()).isNotEmpty();
	}

	@Test
	void breakglassActivationCrud() {
		var bg = breakglass.save(
				BreakglassActivation.create("root@corp", "prod outage", "alert://1", null, "pending", Instant.now()))
				.block();
		assertThat(bg).isNotNull();
		assertThat(breakglass.findByReviewStatus("pending").collectList().block()).isNotEmpty();
	}

	@Test
	void otpStoresHashAndMarkUsed() {
		var otp = otps.save(Otp.create("otp-hash-1", "bob@corp", List.of("deploy"), "10.0.0.0/8",
				Instant.now().plus(5, ChronoUnit.MINUTES))).block();
		assertThat(otp).isNotNull();
		assertThat(otp.used()).isFalse();

		// atomic mark-used lives on the row
		var used = otps.save(new Otp(otp.id(), otp.otpHash(), otp.identity(), otp.allowedPrincipals(), otp.sourceCidr(),
				otp.expiresAt(), true, Instant.now(), otp.version(), otp.createdAt())).block();
		assertThat(used.used()).isTrue();
		assertThat(otps.findByOtpHash("otp-hash-1").block().used()).isTrue();
	}
}
