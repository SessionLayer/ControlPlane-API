package io.sessionlayer.controlplane.platform;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Scope-covering for scopable platform permissions (FR-PADM-2) — must fail
 * closed on a bad scope.
 */
class PlatformScopesTest {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final PlatformScope REQUEST = new PlatformScope(Map.of("env", "prod"), "alice", Instant.now());

	@Test
	void nullOrEmptyScopeIsUnrestricted() {
		assertThat(PlatformScopes.covers(null, REQUEST)).isTrue();
		assertThat(PlatformScopes.covers(JSON.objectNode(), REQUEST)).isTrue();
	}

	@Test
	void typoedFacetKeyFailsClosed() {
		// An unknown facet key (a typo) must NOT silently widen the binding to global.
		assertThat(PlatformScopes.covers(JSON.objectNode().put("environment", "prod"), REQUEST)).isFalse();
	}

	@Test
	void nonObjectScopeFailsClosed() {
		assertThat(PlatformScopes.covers(JSON.arrayNode().add("prod"), REQUEST)).isFalse();
	}

	@Test
	void recognizedFacetCoversOnlyWhenSatisfied() {
		ObjectNode scope = JSON.objectNode();
		scope.set("node_labels", JSON.objectNode().put("env", "prod"));
		assertThat(PlatformScopes.covers(scope, REQUEST)).isTrue();
		assertThat(PlatformScopes.covers(scope, new PlatformScope(Map.of("env", "staging"), "alice", Instant.now())))
				.isFalse();
	}

	@Test
	void scopedBindingCannotAuthorizeAnUnscopedRequest() {
		ObjectNode scope = JSON.objectNode();
		scope.set("node_labels", JSON.objectNode().put("env", "prod"));
		assertThat(PlatformScopes.covers(scope, null)).isFalse();
	}

	@Test
	void degenerateFacetCoversNothing() {
		// A present-but-empty recognized facet imposes NO constraint. It must cover
		// NOTHING (fail closed), matching AuditSearchSql's non-empty-AND predicate — a
		// scoped auditor could otherwise read out-of-scope events by id (the search hid
		// them, the get-by-id matcher did not).
		assertThat(PlatformScopes.covers(JSON.objectNode().set("node_labels", JSON.objectNode()), REQUEST)).isFalse();
		assertThat(PlatformScopes.covers(JSON.objectNode().set("users", JSON.arrayNode()), REQUEST)).isFalse();
		assertThat(PlatformScopes.covers(JSON.objectNode().set("time", JSON.objectNode()), REQUEST)).isFalse();
		// A non-object node_labels / non-array users likewise imposes no constraint.
		assertThat(PlatformScopes.covers(JSON.objectNode().put("node_labels", "x"), REQUEST)).isFalse();
		// A real facet AND-ed with a degenerate one still evaluates the real one.
		ObjectNode mixed = JSON.objectNode();
		mixed.set("node_labels", JSON.objectNode().put("env", "prod"));
		mixed.set("users", JSON.arrayNode());
		assertThat(PlatformScopes.covers(mixed, REQUEST)).isTrue();
	}

	@Test
	void isValidRejectsDegenerateScopeButAllowsUnscopedOrEffective() {
		assertThat(PlatformScopes.isValid(null)).isTrue();
		assertThat(PlatformScopes.isValid(JSON.objectNode())).isTrue(); // unscoped
		assertThat(PlatformScopes.isValid(JSON.objectNode().set("node_labels", JSON.objectNode().put("env", "prod"))))
				.isTrue();
		assertThat(PlatformScopes.isValid(JSON.objectNode().set("users", JSON.arrayNode().add("alice")))).isTrue();
		assertThat(PlatformScopes.isValid(JSON.objectNode().set("node_labels", JSON.objectNode()))).isFalse();
		assertThat(PlatformScopes.isValid(JSON.objectNode().set("users", JSON.arrayNode()))).isFalse();
		assertThat(PlatformScopes.isValid(JSON.objectNode().put("environment", "prod"))).isFalse();
	}
}
