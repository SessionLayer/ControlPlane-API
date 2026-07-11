package io.sessionlayer.controlplane.gateway;

import java.util.regex.Pattern;

/**
 * Allowlist validation for a Gateway name (L1). The name flows into the issued
 * certificate's subject CN and a dNSName SAN, so it is constrained to a
 * conservative DNS-label-ish charset ({@code [A-Za-z0-9._-]}, 1..64 chars) at
 * enrollment — this, together with building the subject via
 * {@code X500NameBuilder} (which escapes), forecloses RDN/SAN injection (e.g.
 * {@code gw1,O=Evil}).
 */
public final class GatewayNames {

	private static final Pattern VALID = Pattern.compile("^[A-Za-z0-9._-]{1,64}$");

	private GatewayNames() {
	}

	public static boolean isValid(String name) {
		return name != null && VALID.matcher(name).matches();
	}
}
