package io.sessionlayer.controlplane.agent;

import java.util.regex.Pattern;

/**
 * Allowlist validation for an Agent's {@code node_name} — the stable per-node
 * enrollment key (FR-JOIN-6). Mirrors {@code GatewayNames} but admits a
 * DNS-subdomain-ish shape (dotted labels, total &le; 253) because a node name
 * is commonly a hostname/FQDN. The name flows into the issued certificate's
 * subject CN and a dNSName SAN, so it is constrained to conservative
 * DNS-label-ish characters at enrollment; together with building the subject
 * via {@code X500NameBuilder} (which RDN-escapes) this forecloses RDN/SAN
 * injection.
 */
public final class AgentNodeNames {

	private static final int MAX_LENGTH = 253;

	// RFC-1123-ish label, additionally tolerating '_' (widely used in internal
	// hostnames and safe to encode). 1..63 chars, no leading/trailing hyphen.
	private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$");

	private AgentNodeNames() {
	}

	public static boolean isValid(String nodeName) {
		if (nodeName == null || nodeName.isEmpty() || nodeName.length() > MAX_LENGTH) {
			return false;
		}
		for (String label : nodeName.split("\\.", -1)) {
			if (!LABEL.matcher(label).matches()) {
				return false;
			}
		}
		return true;
	}
}
