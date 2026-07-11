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
}
