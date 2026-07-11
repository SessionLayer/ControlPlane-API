package io.sessionlayer.controlplane.authz;

import com.google.re2j.Pattern;

/**
 * The anchored-RE2 label operator (FR-AUTHZ-2), compiled on Google's
 * <b>RE2/J</b> — a linear-time engine, NOT {@code java.util.regex}. Because RE2
 * has no backtracking, a catastrophic pattern (e.g. {@code (a+)+$}) matches in
 * time linear in the input, so it cannot ReDoS the decision hot path (a
 * security property — see guardrails). Matching is <b>fully anchored</b>:
 * {@link Pattern#matches} requires the entire label value to match, so a rule
 * cannot be fooled by a substring. Belt-and-suspenders length caps bound work
 * even further.
 */
public final class AnchoredRe2 {

	/** Reject absurd patterns/inputs outright (defense in depth; RE2 is linear). */
	static final int MAX_PATTERN_LENGTH = 1024;
	static final int MAX_INPUT_LENGTH = 4096;

	private AnchoredRe2() {
	}

	/**
	 * True iff {@code value} matches {@code regex} in full (anchored). A too-long
	 * pattern/value or an uncompilable pattern is rejected — the caller fails the
	 * decision closed.
	 */
	public static boolean matches(String regex, String value) {
		if (regex == null || value == null) {
			return false;
		}
		if (regex.length() > MAX_PATTERN_LENGTH) {
			throw new IllegalArgumentException("label regex exceeds max length");
		}
		if (value.length() > MAX_INPUT_LENGTH) {
			return false; // an over-long label value simply cannot be a valid match
		}
		return Pattern.matches(regex, value);
	}
}
