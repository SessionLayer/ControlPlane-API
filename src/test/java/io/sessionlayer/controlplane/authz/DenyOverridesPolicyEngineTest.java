package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The deny-overrides algebra by example (FR-AUTHZ-3/4/6). Properties live in
 * {@link PolicyEnginePropertyTest}.
 */
class DenyOverridesPolicyEngineTest {

	private final PolicyEngine engine = new DenyOverridesPolicyEngine();

	private DataPlaneDecision evaluate(List<DpRule> grants, List<AccessLock> locks, AuthorizationRequest request) {
		return engine.evaluate(request, grants, locks, AuthzFixtures.now());
	}

	@Test
	void defaultDenyWhenNoRuleApplies() {
		DataPlaneDecision decision = evaluate(List.of(), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"));
		assertThat(decision.allowed()).isFalse();
		assertThat(decision.reason()).isEqualTo(DataPlaneDecision.Reason.NO_MATCHING_ALLOW);
	}

	@Test
	void singleAllowGrantsLoginsAndCapabilities() {
		DpRule allow = AuthzFixtures.allow("a", AuthzFixtures.identity("alice"), List.of("deploy"),
				List.of("shell", "exec", "sftp"));
		DataPlaneDecision decision = evaluate(List.of(allow), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"));
		assertThat(decision.allowed()).isTrue();
		assertThat(decision.allowedLogins()).containsExactly("deploy");
		assertThat(decision.capabilities()).containsExactlyInAnyOrder("shell", "exec", "sftp");
		assertThat(decision.matchedRuleName()).isEqualTo("a");
	}

	@Test
	void denyOverridesAnyAllow() {
		DpRule allow = AuthzFixtures.allow("a", AuthzFixtures.identity("alice"), List.of("deploy"), List.of("shell"));
		DpRule deny = AuthzFixtures.deny("d", AuthzFixtures.identity("alice"));
		DataPlaneDecision decision = evaluate(List.of(allow, deny), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"));
		assertThat(decision.allowed()).isFalse();
		assertThat(decision.reason()).isEqualTo(DataPlaneDecision.Reason.EXPLICIT_DENY);
	}

	@Test
	void lockIsTopTierUnOverridable() {
		// An allow (and even JIT-/break-glass-shaped extra allows) all lose to a lock.
		DpRule allow1 = AuthzFixtures.allow("a1", AuthzFixtures.identity("alice"), List.of("deploy"), List.of("shell"));
		DpRule allow2 = AuthzFixtures.allow("jit", AuthzFixtures.identityAll(), List.of("deploy"), List.of("shell"));
		AccessLock lock = AuthzFixtures.lock(AuthzFixtures.lockIdentity("alice"));
		DataPlaneDecision decision = evaluate(List.of(allow1, allow2), List.of(lock),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"));
		assertThat(decision.allowed()).isFalse();
		assertThat(decision.reason()).isEqualTo(DataPlaneDecision.Reason.LOCKED);
	}

	@Test
	void expiredLockDoesNotApply() {
		DpRule allow = AuthzFixtures.allow("a", AuthzFixtures.identity("alice"), List.of("deploy"), List.of("shell"));
		AccessLock expired = new AccessLock(io.sessionlayer.controlplane.data.Uuids.v7(),
				AuthzFixtures.lockIdentity("alice"), "strict", 60, AuthzFixtures.now().minusSeconds(1), "old", "tester",
				null, null, null);
		DataPlaneDecision decision = evaluate(List.of(allow), List.of(expired),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"));
		assertThat(decision.allowed()).isTrue();
	}

	@Test
	void requestedPrincipalMustBeWithinAllowedLogins() {
		DpRule allow = AuthzFixtures.allow("a", AuthzFixtures.identity("alice"), List.of("deploy"), List.of("shell"));
		DataPlaneDecision decision = evaluate(List.of(allow), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "root"));
		assertThat(decision.allowed()).isFalse();
		assertThat(decision.reason()).isEqualTo(DataPlaneDecision.Reason.PRINCIPAL_NOT_ALLOWED);
	}

	@Test
	void capabilitiesAreUnionWithPerGrantDefaults() {
		DpRule silent = AuthzFixtures.allow("silent", AuthzFixtures.identity("alice"), List.of("deploy"), List.of());
		DpRule sftp = AuthzFixtures.allow("sftp", AuthzFixtures.identity("alice"), List.of("deploy"), List.of("sftp"));
		DataPlaneDecision decision = evaluate(List.of(silent, sftp), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"));
		// silent -> {shell,exec} default; sftp -> {sftp}; union.
		assertThat(decision.capabilities()).containsExactlyInAnyOrder("shell", "exec", "sftp");
	}

	@Test
	void agentForwardOnlyWhenExplicitlyGranted() {
		DpRule shellOnly = AuthzFixtures.allow("a", AuthzFixtures.identity("alice"), List.of("deploy"),
				List.of("shell"));
		assertThat(
				evaluate(List.of(shellOnly), List.of(), AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"))
						.capabilities())
				.doesNotContain("agent_forward");

		DpRule withAgent = AuthzFixtures.allow("a", AuthzFixtures.identity("alice"), List.of("deploy"),
				List.of("shell", "agent_forward"));
		assertThat(
				evaluate(List.of(withAgent), List.of(), AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"))
						.capabilities())
				.contains("agent_forward");
	}

	@Test
	void sourceIpDenySuppressesAnOtherwiseMatchingAllow() {
		DpRule allow = DpRule.create("a", AuthzFixtures.identity("alice"), null, AuthzFixtures.sourceDeny("10.0.0.0/8"),
				List.of("deploy"), 3600, List.of("shell"), "allow", "api");
		// from a denied source → the allow is suppressed → default-deny.
		assertThat(evaluate(List.of(allow), List.of(), AuthzFixtures.request("alice", Map.of(), "10.1.2.3", "deploy"))
				.reason()).isEqualTo(DataPlaneDecision.Reason.NO_MATCHING_ALLOW);
		// from an allowed source → the allow applies.
		assertThat(
				evaluate(List.of(allow), List.of(), AuthzFixtures.request("alice", Map.of(), "192.168.1.1", "deploy"))
						.allowed())
				.isTrue();
	}

	@Test
	void grantTtlIsTheMinimumOfContributingAllows() {
		DpRule shortTtl = new DpRule(io.sessionlayer.controlplane.data.Uuids.v7(), "short",
				AuthzFixtures.identity("alice"), null, null, List.of("deploy"), 300, List.of("shell"), "allow", "api",
				null, null, null);
		DpRule longTtl = new DpRule(io.sessionlayer.controlplane.data.Uuids.v7(), "long",
				AuthzFixtures.identity("alice"), null, null, List.of("deploy"), 7200, List.of("shell"), "allow", "api",
				null, null, null);
		DataPlaneDecision decision = evaluate(List.of(shortTtl, longTtl), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"));
		assertThat(decision.grantTtlSeconds()).isEqualTo(300);
	}

	@Test
	void sourceScopedDenyAppliesRegardlessOfSource() {
		// A deny must fail closed: source IP is a deny-only reducer of ALLOWS, never of
		// DENIES (§8.4). An unknown / out-of-range / in-range source all keep the deny.
		DpRule allow = AuthzFixtures.allow("a", AuthzFixtures.identity("alice"), List.of("deploy"), List.of("shell"));
		DpRule deny = AuthzFixtures.sourceScopedDeny("d", AuthzFixtures.identity("alice"),
				AuthzFixtures.sourcePermit("10.0.0.0/8"));
		for (String source : new String[]{null, "192.168.1.1", "10.1.2.3"}) {
			assertThat(evaluate(List.of(allow, deny), List.of(),
					AuthzFixtures.request("alice", Map.of(), source, "deploy")).reason())
					.isEqualTo(DataPlaneDecision.Reason.EXPLICIT_DENY);
		}
	}

	@Test
	void capabilitiesDoNotBleedAcrossPrincipals() {
		DpRule deployGrant = AuthzFixtures.allowForPrincipals("deploy", AuthzFixtures.identity("alice"),
				List.of("deploy"), List.of("shell"));
		DpRule opsGrant = AuthzFixtures.allowForPrincipals("ops", AuthzFixtures.identity("alice"), List.of("ops"),
				List.of("shell", "agent_forward", "x11"));
		DataPlaneDecision asDeploy = evaluate(List.of(deployGrant, opsGrant), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"));
		// Both logins are allowed, but connecting as deploy gets ONLY deploy's caps.
		assertThat(asDeploy.allowedLogins()).containsExactlyInAnyOrder("deploy", "ops");
		assertThat(asDeploy.capabilities()).containsExactly("shell");

		DataPlaneDecision asOps = evaluate(List.of(deployGrant, opsGrant), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "ops"));
		assertThat(asOps.capabilities()).containsExactlyInAnyOrder("shell", "agent_forward", "x11");
	}

	@Test
	void unknownEffectIsTreatedAsDeny() {
		DpRule allow = AuthzFixtures.allow("a", AuthzFixtures.identity("alice"), List.of("deploy"), List.of("shell"));
		DpRule bogus = io.sessionlayer.controlplane.data.config.DpRule.create("bogus", AuthzFixtures.identity("alice"),
				null, null, List.of(), 0, List.of(), "mislabeled", "api");
		assertThat(evaluate(List.of(allow, bogus), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy")).reason())
				.isEqualTo(DataPlaneDecision.Reason.EXPLICIT_DENY);
	}

	@Test
	void lockCanTargetAGroup() {
		DpRule allow = AuthzFixtures.allow("a", AuthzFixtures.groups("admins"), List.of("deploy"), List.of("shell"));
		AccessLock lock = AuthzFixtures.lock(AuthzFixtures.lockGroup("admins"));
		AuthorizationRequest request = new AuthorizationRequest("bob", List.of("admins"), java.util.UUID.randomUUID(),
				Map.of(), "10.0.0.1", "deploy");
		assertThat(engine.evaluate(request, List.of(allow), List.of(lock), AuthzFixtures.now()).reason())
				.isEqualTo(DataPlaneDecision.Reason.LOCKED);
	}

	@Test
	void malformedRuleFailsClosed() {
		DpRule bad = DpRule.create("bad", AuthzFixtures.identityAll(), null, AuthzFixtures.sourceDeny("not-a-cidr"),
				List.of("deploy"), 3600, List.of("shell"), "allow", "api");
		DataPlaneDecision decision = evaluate(List.of(bad), List.of(),
				AuthzFixtures.request("alice", Map.of(), "10.0.0.1", "deploy"));
		assertThat(decision.allowed()).isFalse();
		assertThat(decision.reason()).isEqualTo(DataPlaneDecision.Reason.EVALUATION_ERROR);
	}
}
