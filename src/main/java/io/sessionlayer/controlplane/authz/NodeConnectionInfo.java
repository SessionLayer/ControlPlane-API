package io.sessionlayer.controlplane.authz;

import java.util.List;

/**
 * The CP's per-node connectivity + host-identity answer for an authorized
 * target (Design §9; FR-CONN-1/2/5/7), read from inventory ({@code node} /
 * {@code node_host_key}) and carried on an <b>allow</b>
 * {@link ConnectDecision}. The gRPC layer maps it onto the wire
 * {@code NodeConnection}. Public material only (host-CA keys, the node's
 * enrollment host cert(s), and pinned host public keys, all SSH wire-encoded) —
 * never a private key, and never TOFU: an empty verification set is a
 * misconfigured node that the Gateway aborts (fail closed, §9.3). The host-CA
 * path is emitted only as a complete triple (CA key + cert + principal), so
 * {@code hostCertificates} is non-empty whenever {@code hostCaKeys} is.
 *
 * <p>
 * {@code nodeName} is the node's stable enrollment name. For
 * {@link ConnectorModel#OUTBOUND_AGENT} it is the join key between a session
 * and the agent that owns the node: the Gateway matches it against the dNSName
 * SAN of the agent's mTLS certificate — which the CP itself stamped from
 * {@code node.name} at enrollment/renewal (S14).
 */
public record NodeConnectionInfo(ConnectorModel connectorKind, String nodeName, String dialAddress,
		List<byte[]> hostCaKeys, List<String> expectedPrincipals, List<byte[]> pinnedHostKeys,
		List<byte[]> hostCertificates) {

	/**
	 * The connectivity model resolved from inventory {@code node.connector_kind}.
	 */
	public enum ConnectorModel {
		AGENTLESS, OUTBOUND_AGENT, UNSPECIFIED;

		public static ConnectorModel fromInventory(String connectorKind) {
			return switch (connectorKind == null ? "" : connectorKind) {
				case "agentless" -> AGENTLESS;
				case "agent" -> OUTBOUND_AGENT;
				default -> UNSPECIFIED;
			};
		}
	}

	/** Whether any enrollment-anchored trust is present (host CA or pinned key). */
	public boolean hasHostVerification() {
		return !hostCaKeys.isEmpty() || !pinnedHostKeys.isEmpty();
	}
}
