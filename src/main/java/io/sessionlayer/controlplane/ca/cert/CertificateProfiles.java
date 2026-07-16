package io.sessionlayer.controlplane.ca.cert;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Certificate profiles — the field values SessionLayer stamps for a given
 * certificate role. The one modelled here is the <b>inner-leg session cert</b>
 * (FR-CA-5): a short-lived user cert whose principal is the RBAC-resolved Linux
 * login, whose {@code key_id = session_id + identity} (so the node's own
 * {@code sshd} log records the human behind a shared account), backdated for
 * clock skew, with {@code source-address} pinned and only the granted
 * extensions added (default-deny; {@code agent-forward}/{@code x11} off unless
 * granted).
 *
 * <p>
 * Session Three builds and proves this capability; the per-connection issuance
 * flow that calls it is Session Eight.
 */
public final class CertificateProfiles {

	/** Default inner-leg validity: backdated 2 min for skew, ~5 min forward TTL. */
	public static final Duration DEFAULT_BACKDATE = Duration.ofMinutes(2);
	public static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

	private CertificateProfiles() {
	}

	/**
	 * Build the inner-leg session-cert parameters (FR-CA-5) with default backdating
	 * and TTL. Capabilities map to cert extensions default-deny.
	 *
	 * @param sessionId
	 *            the SessionLayer session id (part of the key id)
	 * @param identity
	 *            the human/subject identity (part of the key id)
	 * @param linuxPrincipal
	 *            the RBAC-resolved Linux login (the cert principal)
	 * @param sourceAddress
	 *            the pinned source-address CIDR list (may be null to omit)
	 * @param capabilities
	 *            the granted capability set (only granted ones become extensions)
	 * @param serial
	 *            the certificate serial
	 * @param now
	 *            the reference instant
	 */
	public static CertificateParameters innerLegSessionCert(String sessionId, String identity, String linuxPrincipal,
			String sourceAddress, Set<String> capabilities, long serial, Instant now) {
		return innerLegSessionCert(sessionId, identity, linuxPrincipal, sourceAddress, capabilities, serial, now,
				DEFAULT_BACKDATE, DEFAULT_TTL);
	}

	public static CertificateParameters innerLegSessionCert(String sessionId, String identity, String linuxPrincipal,
			String sourceAddress, Set<String> capabilities, long serial, Instant now, Duration backdate, Duration ttl) {
		SortedMap<String, String> critical = new TreeMap<>(CertificateParameters.BYTE_ORDER);
		if (sourceAddress != null && !sourceAddress.isBlank()) {
			critical.put("source-address", sourceAddress);
		}
		SortedSet<String> extensions = extensionsFor(capabilities);
		String keyId = sessionId + "+" + identity;
		return new CertificateParameters(serial, CertType.USER, keyId, List.of(linuxPrincipal), now.minus(backdate),
				now.plus(ttl), critical, extensions);
	}

	/**
	 * Build the Gateway OUTER host-cert parameters (FR-ADDR-1, Design §9.3/§11):
	 * the short-lived HOST certificate the Gateway presents on the ProxyJump inner
	 * hop so a stock OpenSSH client accepts it as the target node with no TOFU.
	 * {@code key_id = gateway-host:<gatewayName>} for the node-local audit trail.
	 *
	 * <p>
	 * A host cert carries NO {@code permit-*} extensions and no critical options —
	 * it authenticates the Gateway <b>as the host</b>, not a user's capabilities.
	 * The caller (the CP signing service) is responsible for validating the
	 * principals (non-empty; a HOST cert with empty principals is legal on the wire
	 * but useless).
	 */
	public static CertificateParameters gatewayHostCert(String gatewayName, List<String> principals, Instant validAfter,
			Instant validBefore, long serial) {
		return new CertificateParameters(serial, CertType.HOST, "gateway-host:" + gatewayName, List.copyOf(principals),
				validAfter, validBefore, null, null);
	}

	/**
	 * Map a granted capability set to OpenSSH cert extensions, default-deny: a
	 * capability not present grants no extension. {@code exec}/{@code sftp}/
	 * {@code scp} are enforced at the Gateway channel layer, not via a cert
	 * extension.
	 */
	public static SortedSet<String> extensionsFor(Set<String> capabilities) {
		SortedSet<String> extensions = new TreeSet<>(CertificateParameters.BYTE_ORDER);
		if (capabilities.contains("shell")) {
			extensions.add("permit-pty");
		}
		if (capabilities.contains("port_forward_local") || capabilities.contains("port_forward_remote")) {
			extensions.add("permit-port-forwarding");
		}
		if (capabilities.contains("agent_forward")) {
			extensions.add("permit-agent-forwarding");
		}
		if (capabilities.contains("x11")) {
			extensions.add("permit-X11-forwarding");
		}
		return extensions;
	}
}
