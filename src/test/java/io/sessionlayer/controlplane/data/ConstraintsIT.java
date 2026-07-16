package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.config.CapabilityDef;
import io.sessionlayer.controlplane.data.config.CapabilityDefRepository;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.JitPolicy;
import io.sessionlayer.controlplane.data.config.JitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.Pin;
import io.sessionlayer.controlplane.data.runtime.PinRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

/**
 * Negative / constraint tests (§8.4): every non-trivial CHECK, uniqueness and
 * the 1:1 relationship is proven to reject bad data. Constraint violations
 * surface over R2DBC as {@link DataIntegrityViolationException} (SQLSTATE class
 * 23).
 */
class ConstraintsIT extends AbstractDataIT {

	@Autowired
	private CapabilityDefRepository capabilityDefs;

	@Autowired
	private DpRuleRepository dpRules;

	@Autowired
	private CaConfigRepository caConfigs;

	@Autowired
	private JitPolicyRepository jitPolicies;

	@Autowired
	private NodeRepository nodes;

	@Autowired
	private AgentIdentityRepository agentIdentities;

	@Autowired
	private PinRepository pins;

	@Autowired
	private SshSessionRepository sessions;

	@Autowired
	private RecordingRefRepository recordings;

	@Autowired
	private ObjectMapper objectMapper;

	private void expectRejected(reactor.core.publisher.Mono<?> save) {
		StepVerifier.create(save).verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void badOriginRejected() {
		expectRejected(capabilityDefs.save(CapabilityDef.create("exec", "x", "not-a-valid-origin")));
	}

	@Test
	void badEffectRejected() {
		expectRejected(dpRules.save(DpRule.create("bad-effect", obj(), obj(), null, List.of("deploy"), 300,
				List.of("shell"), "maybe", "api")));
	}

	@Test
	void capabilityNotInEnumRejected() {
		expectRejected(dpRules.save(DpRule.create("bad-cap", obj(), obj(), null, List.of("deploy"), 300,
				List.of("teleport"), "allow", "api")));
	}

	@Test
	void nonPositiveTtlRejected() {
		expectRejected(dpRules.save(
				DpRule.create("bad-ttl", obj(), obj(), null, List.of("deploy"), 0, List.of("shell"), "allow", "api")));
	}

	@Test
	void badCaAlgorithmRejected() {
		expectRejected(caConfigs.save(CaConfig.create("bad-algo", "host", "local", "ref", "rot13", "active", "api")));
	}

	@Test
	void badCaBackendRejected() {
		expectRejected(
				caConfigs.save(CaConfig.create("bad-backend", "user", "sqlite", "ref", "ecdsa-p256", "active", "api")));
	}

	@Test
	void privateKeyMaterialInReferenceRejected() {
		// §2.5 belt-and-suspenders: a PEM private key must not land in a reference
		// column.
		expectRejected(caConfigs.save(CaConfig.create("pem-ca", "session", "local",
				"-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----", "ecdsa-p256", "incoming", "api")));
	}

	@Test
	void agentlessNodeWithoutAddressRejected() {
		expectRejected(nodes
				.save(Node.create("agentless-noaddr", null, obj(), "agentless", "pending", "unknown", null, null)));
	}

	@Test
	void approvalChainLongerThanThreeRejected() {
		var chain = objectMapper.readTree("[{\"kind\":\"email\",\"value\":\"a\"},{\"kind\":\"email\",\"value\":\"b\"},"
				+ "{\"kind\":\"email\",\"value\":\"c\"},{\"kind\":\"email\",\"value\":\"d\"}]");
		expectRejected(jitPolicies.save(JitPolicy.create("too-long", obj(), List.of(), 300, chain, "api")));
	}

	@Test
	void nonObjectSelectorRejected() {
		// jsonb selectors must be objects (CHECK jsonb_typeof = 'object')
		var arrayNode = objectMapper.readTree("[1,2,3]");
		expectRejected(dpRules.save(DpRule.create("arr-sel", arrayNode, obj(), null, List.of("deploy"), 300,
				List.of("shell"), "allow", "api")));
	}

	@Test
	void malformedCidrRejected() {
		expectRejected(pins.save(Pin.create("SHA256:x", "id", "999.999.0.0/8", List.of("deploy"),
				Instant.now().plus(1, ChronoUnit.HOURS))));
	}

	@Test
	void recordingRefIsOneToOne() {
		var node = nodes.save(Node.create("node-1to1", null, obj(), "agent", "active", "healthy", null, null)).block();
		var session = sessions.save(SshSession.create("u", node.id(), node.name(), "deploy", null, null, "standing",
				List.of("shell"), null, null, null, null, 1L, null, Instant.now())).block();
		recordings.save(RecordingRef.create(session.id(), "k1", "ref1", null, null, null)).block();
		// a second recording_ref for the same session violates the UNIQUE(session_id)
		// 1:1
		expectRejected(recordings.save(RecordingRef.create(session.id(), "k2", "ref2", null, null, null)));
	}

	@Test
	void recordingProvenanceIsWriteOnce() {
		var node = nodes.save(Node.create("node-woproven", null, obj(), "agent", "active", "healthy", null, null))
				.block();
		var session = sessions.save(SshSession.create("u", node.id(), node.name(), "deploy", null, null, "standing",
				List.of("shell"), null, null, null, null, 1L, null, Instant.now())).block();
		var rec = recordings.save(RecordingRef.create(session.id(), "k1", "kms://ref1", null, null, null)).block();
		// rewriting the object_key (recording provenance) is evidence tampering ->
		// rejected
		var tampered = new RecordingRef(rec.id(), rec.sessionId(), "k2-tampered", rec.encryptionKeyRef(),
				rec.hashChainHead(), rec.wormMode(), rec.sizeBytes(), rec.retentionUntil(), rec.legalHold(),
				rec.status(), rec.format(), rec.contentDigest(), rec.prunedAt(), rec.deleteMode(), rec.deletedBy(),
				rec.legalHoldReason(), rec.version(), rec.createdAt(), rec.updatedAt());
		expectRejected(recordings.save(tampered));
	}

	@Test
	void sessionDeleteBlockedWhileRecordingExists() {
		var node = nodes.save(Node.create("node-restrict", null, obj(), "agent", "active", "healthy", null, null))
				.block();
		var session = sessions.save(SshSession.create("u", node.id(), node.name(), "deploy", null, null, "standing",
				List.of("shell"), null, null, null, null, 1L, null, Instant.now())).block();
		recordings.save(RecordingRef.create(session.id(), "k1", "kms://ref1", null, null, null)).block();
		// FK is ON DELETE RESTRICT: a session prune cannot cascade-erase recording
		// provenance
		expectRejected(sessions.deleteById(session.id()));
	}

	@Test
	void onlyOneActiveAgentIdentityPerNode() {
		var node = nodes.save(Node.create("node-active", null, obj(), "agent", "active", "healthy", null, null))
				.block();
		agentIdentities.save(AgentIdentity.create(node.id(), "ref1", null, 0, "token", "active", null, null)).block();
		// a second ACTIVE identity for the same node violates the partial unique index
		expectRejected(
				agentIdentities.save(AgentIdentity.create(node.id(), "ref2", null, 0, "token", "active", null, null)));
	}

	@Test
	void revokedSecondIdentityAllowed() {
		var node = nodes.save(Node.create("node-revoked", null, obj(), "agent", "active", "healthy", null, null))
				.block();
		agentIdentities.save(AgentIdentity.create(node.id(), "ref1", null, 0, "token", "active", null, null)).block();
		var revoked = agentIdentities
				.save(AgentIdentity.create(node.id(), "ref2", null, 0, "token", "revoked", null, null)).block();
		assertThat(revoked).isNotNull(); // history rows (non-active) are allowed to accumulate
	}

	private tools.jackson.databind.JsonNode obj() {
		return objectMapper.readTree("{}");
	}
}
