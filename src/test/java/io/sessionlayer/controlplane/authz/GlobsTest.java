package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** The anchored glob label operator. */
class GlobsTest {

	@Test
	void starMatchesAnyRunIncludingEmpty() {
		assertThat(Globs.matches("prod-*", "prod-web-1")).isTrue();
		assertThat(Globs.matches("prod-*", "prod-")).isTrue();
		assertThat(Globs.matches("prod-*", "staging-1")).isFalse();
		assertThat(Globs.matches("*", "anything")).isTrue();
		assertThat(Globs.matches("a*b*c", "axxbyyc")).isTrue();
		assertThat(Globs.matches("a*b*c", "axxbyy")).isFalse();
	}

	@Test
	void questionMatchesExactlyOneChar() {
		assertThat(Globs.matches("web-?", "web-1")).isTrue();
		assertThat(Globs.matches("web-?", "web-12")).isFalse();
		assertThat(Globs.matches("web-?", "web-")).isFalse();
	}

	@Test
	void literalIsWholeStringAnchored() {
		assertThat(Globs.matches("prod", "prod")).isTrue();
		assertThat(Globs.matches("prod", "prod-1")).isFalse();
		assertThat(Globs.matches("prod", "xprod")).isFalse();
	}
}
