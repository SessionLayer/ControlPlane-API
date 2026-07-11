package io.sessionlayer.controlplane.authz;

/**
 * A tiny anchored glob matcher for the {@code glob} label operator
 * (FR-AUTHZ-2): {@code *} matches any run (including empty), {@code ?} matches
 * exactly one character, everything else is literal. Implemented with the
 * classic two-pointer algorithm (linear time, no backtracking explosion — same
 * no-ReDoS posture as the RE2 operator). Matching is whole-string (anchored).
 */
public final class Globs {

	private Globs() {
	}

	public static boolean matches(String pattern, String value) {
		if (pattern == null || value == null) {
			return false;
		}
		int p = 0;
		int v = 0;
		int star = -1;
		int mark = 0;
		while (v < value.length()) {
			if (p < pattern.length() && (pattern.charAt(p) == '?' || pattern.charAt(p) == value.charAt(v))) {
				p++;
				v++;
			} else if (p < pattern.length() && pattern.charAt(p) == '*') {
				star = p++;
				mark = v;
			} else if (star != -1) {
				p = star + 1;
				v = ++mark;
			} else {
				return false;
			}
		}
		while (p < pattern.length() && pattern.charAt(p) == '*') {
			p++;
		}
		return p == pattern.length();
	}
}
