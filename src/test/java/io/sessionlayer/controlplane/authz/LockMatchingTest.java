package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.authz.LockMatching.LockSubject;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * {@link LockMatching} over both selector shapes: the Session-Ten lock-CRUD
 * plural facets (mirroring the frozen {@code LockTarget}) and the S5 singular
 * back-compat form, plus the fail-closed edges (empty/unrecognised → match).
 */
class LockMatchingTest {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	private static final LockSubject ALICE = new LockSubject("alice", "11111111-1111-1111-1111-111111111111",
			Map.of("env", "prod", "tier", "db"), Set.of("deploy", "root"), "deploy", Set.of("admins", "oncall"));

	@Test
	void pluralIdentitiesMatchOnlyTheNamedSubject() {
		assertThat(LockMatching.matches(array("identities", "bob", "alice"), ALICE)).isTrue();
		assertThat(LockMatching.matches(array("identities", "bob", "carol"), ALICE)).isFalse();
	}

	@Test
	void pluralGroupsMatchOnMembership() {
		assertThat(LockMatching.matches(array("groups", "oncall"), ALICE)).isTrue();
		assertThat(LockMatching.matches(array("groups", "wheel"), ALICE)).isFalse();
	}

	@Test
	void pluralNodeIdsMatchTheTargetNode() {
		assertThat(LockMatching.matches(array("node_ids", "11111111-1111-1111-1111-111111111111"), ALICE)).isTrue();
		assertThat(LockMatching.matches(array("node_ids", "22222222-2222-2222-2222-222222222222"), ALICE)).isFalse();
	}

	@Test
	void pluralPrincipalsMatchRequestedOrAllowedLogin() {
		assertThat(LockMatching.matches(array("principals", "deploy"), ALICE)).isTrue(); // requested
		assertThat(LockMatching.matches(array("principals", "root"), ALICE)).isTrue(); // an allowed login
		assertThat(LockMatching.matches(array("principals", "nobody"), ALICE)).isFalse();
	}

	@Test
	void pluralNodeLabelsMatchKeyEqualsValue() {
		assertThat(LockMatching.matches(array("node_labels", "env=prod"), ALICE)).isTrue();
		assertThat(LockMatching.matches(array("node_labels", "env=dev"), ALICE)).isFalse();
	}

	@Test
	void malformedNodeLabelFailsClosed() {
		assertThat(LockMatching.matches(array("node_labels", "no-equals-sign"), ALICE)).isTrue();
	}

	@Test
	void explicitAllMatchesEverything() {
		assertThat(LockMatching.matches(JSON.objectNode().put("all", true), ALICE)).isTrue();
	}

	@Test
	void allFalseWithANonMatchingFacetDoesNotMatch() {
		ObjectNode target = JSON.objectNode().put("all", false);
		target.set("identities", JSON.arrayNode().add("bob"));
		assertThat(LockMatching.matches(target, ALICE)).isFalse();
	}

	@Test
	void singularFacetsStillMatch() {
		assertThat(LockMatching.matches(JSON.objectNode().put("identity", "alice"), ALICE)).isTrue();
		assertThat(LockMatching.matches(JSON.objectNode().put("principal", "root"), ALICE)).isTrue();
	}

	@Test
	void emptyOrUnrecognisedTargetFailsClosed() {
		assertThat(LockMatching.matches(JSON.objectNode(), ALICE)).isTrue();
		assertThat(LockMatching.matches(JSON.objectNode().put("mystery", "x"), ALICE)).isTrue();
	}

	private static ObjectNode array(String key, String... values) {
		ArrayNode array = JSON.arrayNode();
		for (String value : values) {
			array.add(value);
		}
		return JSON.objectNode().set(key, array);
	}
}
