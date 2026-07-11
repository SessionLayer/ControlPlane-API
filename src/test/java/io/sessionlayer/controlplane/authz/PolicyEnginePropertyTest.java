package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * The load-bearing deny-overrides invariants as PROPERTIES (Design §6.1,
 * FR-AUTHZ-3/4/6): the decision is a pure function of the grant <i>set</i>. All
 * pool rules select {@code alice}, so a non-empty subset is applicable and the
 * outcome depends only on the set, not its order.
 */
class PolicyEnginePropertyTest {

	private final PolicyEngine engine = new DenyOverridesPolicyEngine();

	private static final Instant NOW = Instant.parse("2026-07-11T00:00:00Z");
	private static final AuthorizationRequest ALICE = new AuthorizationRequest("alice", List.of(), UUID.randomUUID(),
			Map.of(), "10.0.0.1", null);

	private static final List<DpRule> ALLOW_POOL = List.of(
			AuthzFixtures.allow("p1", AuthzFixtures.identity("alice"), List.of("deploy"), List.of("shell")),
			AuthzFixtures.allow("p2", AuthzFixtures.identity("alice"), List.of("deploy", "ops"),
					List.of("shell", "sftp")),
			AuthzFixtures.allow("p3", AuthzFixtures.identity("alice"), List.of("app"), List.of("exec", "scp")),
			AuthzFixtures.allow("p4", AuthzFixtures.identity("alice"), List.of("deploy"), List.of()),
			AuthzFixtures.allow("p5", AuthzFixtures.identity("alice"), List.of("ci"), List.of("exec", "agent_forward")),
			AuthzFixtures.allow("p6", AuthzFixtures.identity("alice"), List.of("ops"), List.of("x11")));

	private static final DpRule DENY_ALICE = AuthzFixtures.deny("deny-alice", AuthzFixtures.identity("alice"));
	private static final AccessLock LOCK_ALICE = AuthzFixtures.lock(AuthzFixtures.lockIdentity("alice"));

	@Provide
	Arbitrary<List<DpRule>> allowSubsets() {
		return Arbitraries.subsetOf(ALLOW_POOL).map(ArrayList::new);
	}

	@Provide
	Arbitrary<List<DpRule>> nonEmptyAllowSubsets() {
		return Arbitraries.subsetOf(ALLOW_POOL).filter(s -> !s.isEmpty()).map(ArrayList::new);
	}

	@Property
	void decisionIsOrderIndependent(@ForAll("allowSubsets") List<DpRule> rules, @ForAll long seed) {
		DataPlaneDecision base = engine.evaluate(ALICE, rules, List.of(), NOW);
		List<DpRule> shuffled = new ArrayList<>(rules);
		Collections.shuffle(shuffled, new Random(seed));
		List<DpRule> reversed = new ArrayList<>(rules);
		Collections.reverse(reversed);
		assertThat(engine.evaluate(ALICE, shuffled, List.of(), NOW)).isEqualTo(base);
		assertThat(engine.evaluate(ALICE, reversed, List.of(), NOW)).isEqualTo(base);
	}

	@Property
	void anyMatchingDenyBeatsAllAllows(@ForAll("allowSubsets") List<DpRule> allows) {
		List<DpRule> withDeny = new ArrayList<>(allows);
		withDeny.add(DENY_ALICE);
		Collections.shuffle(withDeny, new Random(allows.size()));
		assertThat(engine.evaluate(ALICE, withDeny, List.of(), NOW).reason())
				.isEqualTo(DataPlaneDecision.Reason.EXPLICIT_DENY);
	}

	@Property
	void aMatchingLockBeatsEverything(@ForAll("allowSubsets") List<DpRule> allows) {
		// allows (incl. JIT-/break-glass-shaped grants) all lose to a matching lock.
		assertThat(engine.evaluate(ALICE, allows, List.of(LOCK_ALICE), NOW).reason())
				.isEqualTo(DataPlaneDecision.Reason.LOCKED);
	}

	@Property
	void unselectedIdentityIsDefaultDenied(@ForAll("allowSubsets") List<DpRule> allows) {
		AuthorizationRequest nobody = new AuthorizationRequest("nobody", List.of(), UUID.randomUUID(), Map.of(),
				"10.0.0.1", null);
		assertThat(engine.evaluate(nobody, allows, List.of(), NOW).allowed()).isFalse();
	}

	@Property
	void capabilitiesAreTheUnionOfApplicableAllows(@ForAll("nonEmptyAllowSubsets") List<DpRule> allows) {
		DataPlaneDecision decision = engine.evaluate(ALICE, allows, List.of(), NOW);
		Set<String> expected = new TreeSet<>();
		for (DpRule rule : allows) {
			expected.addAll(Capabilities.effective(new HashSet<>(rule.capabilities())));
		}
		assertThat(decision.allowed()).isTrue();
		assertThat(decision.capabilities()).isEqualTo(expected);
	}
}
