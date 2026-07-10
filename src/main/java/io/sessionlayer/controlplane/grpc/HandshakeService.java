package io.sessionlayer.controlplane.grpc;

import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.protobuf.ProtoUtils;
import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.config.ComponentDescriptor;
import io.sessionlayer.controlplane.grpc.v1.ClientHello;
import io.sessionlayer.controlplane.grpc.v1.ComponentInfo;
import io.sessionlayer.controlplane.grpc.v1.HandshakeGrpc;
import io.sessionlayer.controlplane.grpc.v1.NoCommonVersion;
import io.sessionlayer.controlplane.grpc.v1.ProtocolVersion;
import io.sessionlayer.controlplane.grpc.v1.ServerHello;
import io.sessionlayer.controlplane.protocol.ProtocolVersions;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Server side of the CP&lt;-&gt;Gateway version-negotiation plane
 * ({@code handshake.proto}) — the only RPC implemented in Session One (FR-HA-9
 * / Design D33).
 *
 * <p>
 * Spring gRPC binds this {@link io.grpc.BindableService} bean to the standalone
 * Netty gRPC server on {@code :9090}. That server is PLAINTEXT and dev-only
 * this session; mTLS channel authentication plus per-RPC, session-bound
 * authorization arrive in Session Four (Design §15). Negotiation carries no
 * secrets, so negotiating before authentication is acceptable.
 *
 * <p>
 * Non-blocking: {@link #negotiate} is a pure function of the two version ranges
 * and performs no I/O, so it completes inline on the gRPC event-loop thread
 * with no blocking hop.
 */
@Service
public class HandshakeService extends HandshakeGrpc.HandshakeImplBase {

	private static final Logger LOG = LoggerFactory.getLogger(HandshakeService.class);

	/**
	 * Typed trailer carrying the diagnostic {@link NoCommonVersion} on rejection.
	 * The proto's own message is attached as a binary metadata trailer (idiomatic
	 * grpc-java, no extra dependency); Session Four can promote this to a
	 * {@code google.rpc.Status} error detail if richer clients need it. The
	 * handshake spec makes attaching the detail a SHOULD, not a MUST.
	 */
	private static final Metadata.Key<NoCommonVersion> NO_COMMON_VERSION_KEY = ProtoUtils
			.keyForProto(NoCommonVersion.getDefaultInstance());

	private final ComponentDescriptor descriptor;

	public HandshakeService(ComponentDescriptor descriptor) {
		this.descriptor = descriptor;
	}

	@Override
	public void negotiate(ClientHello request, StreamObserver<ServerHello> responseObserver) {
		ComponentInfo client = request.getClient();
		ProtocolVersion serverMin = ProtocolVersions.SUPPORTED_MIN;
		ProtocolVersion serverMax = ProtocolVersions.SUPPORTED_MAX;

		Optional<ProtocolVersion> selected = VersionNegotiator.highestCommon(client.getProtocolMin(),
				client.getProtocolMax(), serverMin, serverMax);

		if (selected.isEmpty()) {
			responseObserver.onError(noCommonVersion(client, serverMin, serverMax));
			return;
		}

		ServerHello reply = ServerHello.newBuilder().setServer(serverComponentInfo()).setSelected(selected.get())
				.build();
		responseObserver.onNext(reply);
		responseObserver.onCompleted();
	}

	private ComponentInfo serverComponentInfo() {
		return ComponentInfo.newBuilder().setName(descriptor.name()).setSemver(descriptor.version())
				.setProtocolMin(ProtocolVersions.SUPPORTED_MIN).setProtocolMax(ProtocolVersions.SUPPORTED_MAX).build();
	}

	private StatusRuntimeException noCommonVersion(ComponentInfo client, ProtocolVersion serverMin,
			ProtocolVersion serverMax) {
		String description = String.format("no common protocol version: client=[%s,%s] server=[%s,%s]",
				ProtocolVersions.display(client.getProtocolMin()), ProtocolVersions.display(client.getProtocolMax()),
				ProtocolVersions.display(serverMin), ProtocolVersions.display(serverMax));
		LOG.warn("Handshake.Negotiate rejected: {}", description);

		Metadata trailers = new Metadata();
		trailers.put(NO_COMMON_VERSION_KEY, NoCommonVersion.newBuilder().setClientMin(client.getProtocolMin())
				.setClientMax(client.getProtocolMax()).setServerMin(serverMin).setServerMax(serverMax).build());

		return Status.FAILED_PRECONDITION.withDescription(description).asRuntimeException(trailers);
	}
}
