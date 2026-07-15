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
 *
 * <p>
 * The {@code owner*} fields carry the HA presence/ownership answer (Design
 * §10.2/§10.3; FR-HA-2/5) and are populated only for an
 * {@link ConnectorModel#OUTBOUND_AGENT} node with a <b>fresh</b> presence
 * owner; they are empty otherwise (no fresh owner, or agentless).
 * {@code owningGatewayId} is the owning Gateway's {@code gateway_identity.name}
 * — the HA routing key the rest of the plane speaks (the ingress compares it to
 * its own name; the owner subscribes to {@code sl.dialback.<name>}) — surfaced
 * verbatim from the presence row the {@code Presence} write path recorded.
 */
public record NodeConnectionInfo(ConnectorModel connectorKind, String nodeName, String dialAddress,
		List<byte[]> hostCaKeys, List<String> expectedPrincipals, List<byte[]> pinnedHostKeys,
		List<byte[]> hostCertificates, String owningGatewayId, String owningGatewayAddr, long ownerNonce,
		String ownerNonceId) {

	/** Build with no HA owner (agentless, or an agent node with no fresh owner). */
	public NodeConnectionInfo(ConnectorModel connectorKind, String nodeName, String dialAddress,
			List<byte[]> hostCaKeys, List<String> expectedPrincipals, List<byte[]> pinnedHostKeys,
			List<byte[]> hostCertificates) {
		this(connectorKind, nodeName, dialAddress, hostCaKeys, expectedPrincipals, pinnedHostKeys, hostCertificates, "",
				"", 0L, "");
	}

	/**
	 * A copy carrying the fresh HA presence owner (id, advertise addr, fencing
	 * nonce).
	 */
	public NodeConnectionInfo withOwner(String owningGatewayId, String owningGatewayAddr, long ownerNonce,
			String ownerNonceId) {
		return new NodeConnectionInfo(connectorKind, nodeName, dialAddress, hostCaKeys, expectedPrincipals,
				pinnedHostKeys, hostCertificates, owningGatewayId, owningGatewayAddr, ownerNonce, ownerNonceId);
	}

	/**
	 * Whether a fresh HA presence owner is present (routing populates the wire).
	 */
	public boolean hasOwner() {
		return owningGatewayId != null && !owningGatewayId.isEmpty();
	}

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
