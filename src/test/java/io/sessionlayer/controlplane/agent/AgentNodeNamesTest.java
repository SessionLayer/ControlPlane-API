package io.sessionlayer.controlplane.agent;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AgentNodeNamesTest {

	@Test
	void acceptsDnsSubdomainShapes() {
		assertThat(AgentNodeNames.isValid("node1")).isTrue();
		assertThat(AgentNodeNames.isValid("web-01.prod.corp")).isTrue();
		assertThat(AgentNodeNames.isValid("db_primary")).isTrue();
		assertThat(AgentNodeNames.isValid("a")).isTrue();
		assertThat(AgentNodeNames.isValid("a" + ".b".repeat(100))).isTrue();
	}

	@Test
	void rejectsMalformedOrInjectionShapes() {
		assertThat(AgentNodeNames.isValid(null)).isFalse();
		assertThat(AgentNodeNames.isValid("")).isFalse();
		assertThat(AgentNodeNames.isValid(".leading")).isFalse();
		assertThat(AgentNodeNames.isValid("trailing.")).isFalse();
		assertThat(AgentNodeNames.isValid("double..dot")).isFalse();
		assertThat(AgentNodeNames.isValid("-hyphenstart")).isFalse();
		assertThat(AgentNodeNames.isValid("has space")).isFalse();
		assertThat(AgentNodeNames.isValid("gw1,O=Evil")).isFalse(); // RDN injection
		assertThat(AgentNodeNames.isValid("a".repeat(254))).isFalse(); // too long
	}
}
