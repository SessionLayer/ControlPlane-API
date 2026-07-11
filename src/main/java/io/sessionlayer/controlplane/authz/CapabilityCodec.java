package io.sessionlayer.controlplane.authz;

import io.sessionlayer.controlplane.grpc.v1.Capability;
import java.util.List;
import java.util.Map;

/** Maps the schema capability strings to/from the proto {@link Capability}. */
public final class CapabilityCodec {

	private static final Map<String, Capability> TO_PROTO = Map.of(Capabilities.SHELL, Capability.CAPABILITY_SHELL,
			Capabilities.EXEC, Capability.CAPABILITY_EXEC, Capabilities.SFTP, Capability.CAPABILITY_SFTP,
			Capabilities.SCP, Capability.CAPABILITY_SCP, Capabilities.PORT_FORWARD_LOCAL,
			Capability.CAPABILITY_PORT_FORWARD_LOCAL, Capabilities.PORT_FORWARD_REMOTE,
			Capability.CAPABILITY_PORT_FORWARD_REMOTE, Capabilities.AGENT_FORWARD, Capability.CAPABILITY_AGENT_FORWARD,
			Capabilities.X11, Capability.CAPABILITY_X11);

	private CapabilityCodec() {
	}

	public static Capability toProto(String capability) {
		Capability proto = TO_PROTO.get(capability);
		if (proto == null) {
			throw new IllegalArgumentException("unknown capability: " + capability);
		}
		return proto;
	}

	public static List<Capability> toProto(List<String> capabilities) {
		return capabilities.stream().map(CapabilityCodec::toProto).toList();
	}
}
