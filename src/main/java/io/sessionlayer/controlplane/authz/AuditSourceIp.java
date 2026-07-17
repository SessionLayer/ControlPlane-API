package io.sessionlayer.controlplane.authz;

import java.net.InetAddress;

/**
 * Strict literal validator for the audit {@code source_ip} column, matching
 * Postgres {@code ::inet} (the {@code runtime.is_ip_or_cidr} CHECK) exactly: a
 * canonical dotted-quad IPv4 (four {@code 0-255} octets, no leading zeros, no
 * integer/abbreviated forms) or a valid IPv6 literal. Non-resolving (never a
 * DNS lookup) so it is safe on the reactive event loop.
 *
 * <p>
 * The audit writer keeps only values this accepts and drops the rest to
 * {@code null}: a value {@code ::inet} would reject must never reach the
 * column, or the INSERT's CHECK violation would roll back the enclosing
 * transaction — on the allow path that turns a successful connect into a
 * fail-closed deny, and on the deny path it silently loses the decision-log row
 * (FR-AUD-7). {@link Cidrs} (the FR-AUTH-15 reducer) is intentionally NOT
 * tightened here — its leniency is a separate concern with its own fail-closed
 * semantics.
 */
public final class AuditSourceIp {

	private AuditSourceIp() {
	}

	/** True iff {@code value} is a literal Postgres {@code ::inet} would accept. */
	public static boolean isCanonicalLiteral(String value) {
		if (value == null) {
			return false;
		}
		String trimmed = value.trim();
		if (trimmed.isEmpty()) {
			return false;
		}
		return trimmed.indexOf(':') >= 0 ? parsesAsLiteral(trimmed) : isDottedQuadIpv4(trimmed);
	}

	// An IPv6 literal (has a colon): accept iff it parses WITHOUT a name lookup.
	private static boolean parsesAsLiteral(String value) {
		try {
			InetAddress.ofLiteral(value);
			return true;
		} catch (IllegalArgumentException notALiteral) {
			return false;
		}
	}

	// Postgres ::inet requires the canonical four-octet form; it rejects integer
	// ("16909060"), short ("1.2.3"/"127.1") and leading-zero ("010.0.0.1") IPv4
	// that
	// InetAddress would otherwise accept via inet_aton-style parsing.
	private static boolean isDottedQuadIpv4(String value) {
		String[] octets = value.split("\\.", -1);
		if (octets.length != 4) {
			return false;
		}
		for (String octet : octets) {
			int length = octet.length();
			if (length < 1 || length > 3) {
				return false;
			}
			if (length > 1 && octet.charAt(0) == '0') {
				return false;
			}
			int parsed = 0;
			for (int i = 0; i < length; i++) {
				char c = octet.charAt(i);
				if (c < '0' || c > '9') {
					return false;
				}
				parsed = parsed * 10 + (c - '0');
			}
			if (parsed > 255) {
				return false;
			}
		}
		return true;
	}
}
