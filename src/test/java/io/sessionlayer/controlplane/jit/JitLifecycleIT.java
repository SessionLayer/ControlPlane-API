package io.sessionlayer.controlplane.jit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.sessionlayer.controlplane.data.config.JitPolicy;
import io.sessionlayer.controlplane.data.config.JitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.JitRequest;
import io.sessionlayer.controlplane.data.runtime.JitRequestRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

/**
 * The JIT state machine end to end through the real repos (FR-ACC-2/3/4):
 * submit, the two-clock expiry, the ordered approval chain with the
 * self-approval hard invariant, and revoke → Lock. Deterministic: expiry is
 * driven by seeding past clocks and calling {@code expireOverdue()} explicitly
 * (the scheduler's own delay never fires during the test).
 */
class JitLifecycleIT extends AbstractAuthIT {

	@Autowired
	JitLifecycleService jit;
	@Autowired
	JitRequestRepository requests;
	@Autowired
	JitPolicyRepository policies;
	@Autowired
	NodeRepository nodes;
	@Autowired
	AccessLockRepository locks;
	@Autowired
	ObjectMapper mapper;

	@Test
	void zeroChainAutoApprovesAndProducesAUsableGrant() {
		String zone = unique();
		UUID node = seedNode(zone);
		seedPolicy(zone, 3600);
		String requester = "alice-" + unique();

		JitRequest submitted = jit.submit(requester, node, "deploy", List.of("shell"), "prod fix").block();
		assertThat(submitted.state()).isEqualTo(JitRequest.APPROVED);
		assertThat(submitted.grantExpiresAt()).isAfter(Instant.now());

		JitRequest grant = jit.findUsableGrant(requester, node, "deploy", Instant.now()).block();
		assertThat(grant).isNotNull();
		assertThat(jit.markActive(grant).block().state()).isEqualTo(JitRequest.ACTIVE);
	}

	@Test
	void oneLevelChainPendsThenApproves() {
		String zone = unique();
		UUID node = seedNode(zone);
		seedPolicy(zone, 3600, level("email", "boss@corp"));
		String requester = "bob-" + unique();

		JitRequest submitted = jit.submit(requester, node, "deploy", List.of(), "need access").block();
		assertThat(submitted.state()).isEqualTo(JitRequest.PENDING_APPROVAL);
		assertThat(submitted.grantExpiresAt()).isNull(); // the grant clock starts at approval

		JitRequest approved = jit.approve(submitted.id(), "boss@corp", List.of(), "ok").block();
		assertThat(approved.state()).isEqualTo(JitRequest.APPROVED);
		assertThat(approved.grantExpiresAt()).isAfter(Instant.now());
		assertThat(jit.findUsableGrant(requester, node, "deploy", Instant.now()).block()).isNotNull();
	}

	@Test
	void selfApprovalIsImpossibleEvenIfRequesterIsAConfiguredApprover() {
		String zone = unique();
		UUID node = seedNode(zone);
		// The requester's own email IS the approver level — self-approval must STILL
		// fail.
		seedPolicy(zone, 3600, level("email", "carol@corp"));
		JitRequest submitted = jit.submit("carol@corp", node, "deploy", List.of(), "self").block();

		JitException failure = catchThrowableOfType(JitException.class,
				() -> jit.approve(submitted.id(), "carol@corp", List.of(), "me").block());
		assertThat(failure.reason()).isEqualTo(JitException.Reason.SELF_APPROVAL);
		assertThat(requests.findById(submitted.id()).block().state()).isEqualTo(JitRequest.PENDING_APPROVAL);
	}

	@Test
	void twoLevelChainRequiresTwoDistinctApprovers() {
		String zone = unique();
		UUID node = seedNode(zone);
		seedPolicy(zone, 3600, level("oidc_group", "l1"), level("oidc_group", "l2"));
		JitRequest submitted = jit.submit("dave-" + unique(), node, "deploy", List.of(), "two-level").block();

		JitRequest afterFirst = jit.approve(submitted.id(), "approver-a@corp", List.of("l1"), null).block();
		assertThat(afterFirst.state()).isEqualTo(JitRequest.PENDING_APPROVAL); // still needs level 2

		// The same approver cannot act twice — an N-level chain needs N DISTINCT
		// approvers.
		JitException reacted = catchThrowableOfType(JitException.class,
				() -> jit.approve(submitted.id(), "approver-a@corp", List.of("l1", "l2"), null).block());
		assertThat(reacted.reason()).isEqualTo(JitException.Reason.ALREADY_ACTED);

		JitRequest done = jit.approve(submitted.id(), "approver-b@corp", List.of("l2"), null).block();
		assertThat(done.state()).isEqualTo(JitRequest.APPROVED);
	}

	@Test
	void denyIsTerminal() {
		String zone = unique();
		UUID node = seedNode(zone);
		seedPolicy(zone, 3600, level("email", "boss@corp"));
		JitRequest submitted = jit.submit("erin-" + unique(), node, "deploy", List.of(), "x").block();

		assertThat(jit.deny(submitted.id(), "boss@corp", List.of(), "not now").block().state())
				.isEqualTo(JitRequest.DENIED);

		JitException notPending = catchThrowableOfType(JitException.class,
				() -> jit.approve(submitted.id(), "boss@corp", List.of(), null).block());
		assertThat(notPending.reason()).isEqualTo(JitException.Reason.NOT_PENDING);
	}

	@Test
	void approvalWindowExpiryTransitionsToExpired() {
		String zone = unique();
		UUID node = seedNode(zone);
		JitRequest overdue = requests
				.save(JitRequest.create("frank-" + unique(), node, "node", null, "deploy", List.of("shell"), "late",
						JitRequest.PENDING_APPROVAL, UUID.randomUUID(), "p", mapper.createArrayNode(),
						mapper.createArrayNode(), Instant.now().minus(1, ChronoUnit.MINUTES), null, Instant.now()))
				.block();

		assertThat(jit.expireOverdue().block()).isGreaterThanOrEqualTo(1L);
		assertThat(requests.findById(overdue.id()).block().state()).isEqualTo(JitRequest.EXPIRED);
	}

	@Test
	void overdueGrantIsNeverServedAndExpires() {
		String zone = unique();
		UUID node = seedNode(zone);
		String requester = "gina-" + unique();
		JitRequest stale = requests.save(JitRequest.create(requester, node, "node", null, "deploy", List.of("shell"),
				"old", JitRequest.APPROVED, UUID.randomUUID(), "p", mapper.createArrayNode(), mapper.createArrayNode(),
				Instant.now().minus(2, ChronoUnit.HOURS), Instant.now().minus(1, ChronoUnit.MINUTES), Instant.now()))
				.block();

		// Never serve an overdue grant (lazy expiry on read).
		assertThat(jit.findUsableGrant(requester, node, "deploy", Instant.now()).blockOptional()).isEmpty();
		jit.expireOverdue().block();
		assertThat(requests.findById(stale.id()).block().state()).isEqualTo(JitRequest.EXPIRED);
	}

	@Test
	void revokeWritesAStrictLockOnIdentityAndNode() {
		String zone = unique();
		UUID node = seedNode(zone);
		seedPolicy(zone, 3600);
		String requester = "hank-" + unique();
		JitRequest approved = jit.submit(requester, node, "deploy", List.of("shell"), "fix").block();

		assertThat(jit.revoke(approved.id(), "admin@corp", "incident").block().state()).isEqualTo(JitRequest.REVOKED);

		List<AccessLock> all = locks.findAll().collectList().block();
		assertThat(all).anySatisfy(lock -> {
			assertThat(lock.mode()).isEqualTo("strict");
			assertThat(lock.targetSelector().get("identities").get(0).stringValue()).isEqualTo(requester);
			assertThat(lock.targetSelector().get("node_ids").get(0).stringValue()).isEqualTo(node.toString());
		});
	}

	@Test
	void submitAgainstANonRequestableTargetIsRejected() {
		UUID node = seedNode(unique()); // a zone no JIT policy governs
		JitException failure = catchThrowableOfType(JitException.class,
				() -> jit.submit("ivy-" + unique(), node, "deploy", List.of(), "x").block());
		assertThat(failure.reason()).isEqualTo(JitException.Reason.NOT_REQUESTABLE);
	}

	// Each test gets its OWN zone label so exactly one JIT policy governs its node.
	// Policy matching picks the first policy whose selector matches the node, and
	// this class shares one Postgres — without a per-test zone every test's policy
	// would match every other test's node.
	private UUID seedNode(String zone) {
		ObjectNode labels = mapper.createObjectNode().put("env", "prod").put("jitzone", zone);
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedPolicy(String zone, int maxTtl, ObjectNode... levels) {
		ObjectNode targetSelector = mapper.createObjectNode();
		targetSelector.set("jitzone", mapper.createObjectNode().put("op", "eq").put("value", zone));
		ArrayNode chain = mapper.createArrayNode();
		for (ObjectNode level : levels) {
			chain.add(level);
		}
		policies.save(
				JitPolicy.create("jit-" + unique(), targetSelector, List.of("shell", "exec"), maxTtl, chain, "api"))
				.block();
	}

	private ObjectNode level(String kind, String value) {
		return mapper.createObjectNode().put("kind", kind).put("value", value);
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
