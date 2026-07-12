package io.sessionlayer.controlplane.authz;

/**
 * Serializes a {@link DecisionContext} to the proto message and its canonical
 * signed bytes. The signed bytes are the proto message's deterministic
 * serialization (the message has no map fields, so field-order encoding is
 * stable across Java protobuf and Rust prost); the Gateway (S10) recomputes and
 * verifies against them. See VERSIONING.md §6.
 */
public final class DecisionContextCodec {

	private DecisionContextCodec() {
	}

	public static io.sessionlayer.controlplane.grpc.v1.DecisionContext toProto(DecisionContext ctx) {
		return io.sessionlayer.controlplane.grpc.v1.DecisionContext.newBuilder().setNodeId(str(ctx.nodeId()))
				.setNodeName(nullToEmpty(ctx.nodeName())).addAllAllowedLogins(ctx.allowedLogins())
				.addAllCapabilities(CapabilityCodec.toProto(ctx.capabilities()))
				.setPrincipal(nullToEmpty(ctx.principal()))
				.setGrantExpiryEpochSeconds(ctx.grantExpiry().getEpochSecond()).setPolicyEpoch(ctx.policyEpoch())
				.setDecisionTtlSeconds(ctx.decisionTtl().toSeconds()).setGatewayId(str(ctx.gatewayId()))
				.setSessionId(str(ctx.sessionId())).setSourceAddress(nullToEmpty(ctx.sourceAddress()))
				.setIssuedAtEpochSeconds(ctx.issuedAt().getEpochSecond()).setIdentity(nullToEmpty(ctx.identity()))
				.addAllIdentityGroups(ctx.identityGroups()).addAllNodeLabels(ctx.nodeLabels()).build();
	}

	/** The exact bytes signed by the decision-context signer. */
	public static byte[] canonicalBytes(io.sessionlayer.controlplane.grpc.v1.DecisionContext proto) {
		return proto.toByteArray();
	}

	private static String str(java.util.UUID id) {
		return id == null ? "" : id.toString();
	}

	private static String nullToEmpty(String value) {
		return value == null ? "" : value;
	}
}
