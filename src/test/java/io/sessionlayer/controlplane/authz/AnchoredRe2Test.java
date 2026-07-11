package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * The anchored, linear-time (RE2/J) label-regex operator — no ReDoS
 * (FR-AUTHZ-2).
 */
class AnchoredRe2Test {

	@Test
	void matchesTheEntireValueOnly() {
		assertThat(AnchoredRe2.matches("prod-[0-9]+", "prod-42")).isTrue();
		// anchored: a partial/substring match does NOT satisfy the operator.
		assertThat(AnchoredRe2.matches("prod-[0-9]+", "prod-42-extra")).isFalse();
		assertThat(AnchoredRe2.matches("prod-[0-9]+", "x-prod-42")).isFalse();
		assertThat(AnchoredRe2.matches("[a-z]+", "abc123")).isFalse();
	}

	@Test
	void catastrophicPatternCompletesInBoundedTime() {
		// (a+)+$ against a long non-matching input is the classic exponential-blowup
		// case
		// for a backtracking engine (java.util.regex). RE2 evaluates it in linear time.
		String evil = "(a+)+$";
		String input = "a".repeat(4000) + "!";
		long startNanos = System.nanoTime();
		boolean matched = AnchoredRe2.matches(evil, input);
		long elapsedMillis = (System.nanoTime() - startNanos) / 1_000_000;
		assertThat(matched).isFalse();
		assertThat(elapsedMillis).as("RE2 stays linear — well under a second").isLessThan(1000L);
	}

	@Test
	void overlongPatternIsRejected() {
		assertThatThrownBy(() -> AnchoredRe2.matches("a".repeat(AnchoredRe2.MAX_PATTERN_LENGTH + 1), "x"))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void overlongInputCannotMatch() {
		assertThat(AnchoredRe2.matches(".*", "a".repeat(AnchoredRe2.MAX_INPUT_LENGTH + 1))).isFalse();
	}
}
