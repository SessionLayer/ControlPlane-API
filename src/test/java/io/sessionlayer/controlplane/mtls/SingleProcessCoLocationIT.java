package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.sessionlayer.controlplane.config.ComponentDescriptor;
import io.sessionlayer.controlplane.grpc.v1.ClientHello;
import io.sessionlayer.controlplane.grpc.v1.ComponentInfo;
import io.sessionlayer.controlplane.grpc.v1.HandshakeGrpc;
import io.sessionlayer.controlplane.grpc.v1.ServerHello;
import io.sessionlayer.controlplane.protocol.ProtocolVersions;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * FR-BOOT-5 — the single-instance CP+Gateway+coordination co-location posture,
 * with Postgres the only external dependency. The whole CP context boots
 * against only a Postgres container (no other network dep), and its gRPC
 * service surface (the real {@code List<BindableService>} beans a co-located
 * Gateway would bind) is servable over the <b>in-process</b> gRPC transport —
 * no socket, no TLS — the co-location "internal gRPC is an in-process call"
 * contract (Design §5.4 / §10.4). Exercised via the unauthenticated
 * {@code Handshake} RPC (the transport is the co-location seam; mutual auth is
 * a separate concern on the outward mTLS server).
 */
class SingleProcessCoLocationIT extends AbstractMtlsIT {

	@Autowired
	private List<BindableService> grpcServices;

	@Test
	void theCpGrpcSurfaceServesInProcessWithPostgresTheOnlyExternalDependency() throws Exception {
		String name = InProcessServerBuilder.generateName();
		InProcessServerBuilder builder = InProcessServerBuilder.forName(name).directExecutor();
		grpcServices.forEach(builder::addService);
		Server server = builder.build().start();
		ManagedChannel channel = InProcessChannelBuilder.forName(name).directExecutor().build();
		try {
			ServerHello reply = HandshakeGrpc.newBlockingStub(channel)
					.negotiate(ClientHello.newBuilder()
							.setClient(ComponentInfo.newBuilder().setName("SessionLayer Gateway").setSemver("0.1.0")
									.setProtocolMin(ProtocolVersions.of(1, 0)).setProtocolMax(ProtocolVersions.of(1, 0))
									.build())
							.build());

			// The co-located Gateway reaches the CP over the in-process channel and
			// negotiates the protocol — no external dependency beyond the Postgres the
			// context already booted against.
			assertThat(reply.getSelected().getMajor()).isEqualTo(1);
			assertThat(reply.getSelected().getMinor()).isEqualTo(0);
			assertThat(reply.getServer().getName()).isEqualTo(ComponentDescriptor.NAME);
		} finally {
			channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
			server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
	}
}
