package io.sessionlayer.controlplane.grpc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.sessionlayer.controlplane.config.ComponentDescriptor;
import io.sessionlayer.controlplane.grpc.v1.ClientHello;
import io.sessionlayer.controlplane.grpc.v1.ComponentInfo;
import io.sessionlayer.controlplane.grpc.v1.HandshakeGrpc;
import io.sessionlayer.controlplane.grpc.v1.ServerHello;
import io.sessionlayer.controlplane.protocol.ProtocolVersions;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * End-to-end test of the {@code Handshake.Negotiate} RPC over a real
 * (in-process) gRPC channel, so protobuf marshalling and the gRPC status
 * contract are exercised — deterministic and port-free.
 */
class HandshakeServiceTest {

	private Server server;
	private ManagedChannel channel;
	private HandshakeGrpc.HandshakeBlockingStub stub;

	@BeforeEach
	void startInProcessServer() throws Exception {
		String name = InProcessServerBuilder.generateName();
		server = InProcessServerBuilder.forName(name).directExecutor()
				.addService(new HandshakeService(new ComponentDescriptor("0.1.0"))).build().start();
		channel = InProcessChannelBuilder.forName(name).directExecutor().build();
		stub = HandshakeGrpc.newBlockingStub(channel);
	}

	@AfterEach
	void stopInProcessServer() throws Exception {
		channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
	}

	@Test
	void negotiateResolvesOnePointZeroAndEchoesServerIdentity() {
		ServerHello reply = stub.negotiate(clientHello(1, 0, 1, 0));

		assertThat(reply.getSelected().getMajor()).isEqualTo(1);
		assertThat(reply.getSelected().getMinor()).isEqualTo(0);
		assertThat(reply.getServer().getName()).isEqualTo(ComponentDescriptor.NAME);
		assertThat(reply.getServer().getSemver()).isEqualTo("0.1.0");
		assertThat(reply.getServer().getProtocolMax()).isEqualTo(ProtocolVersions.SUPPORTED_MAX);
	}

	@Test
	void negotiateFailsClosedWithFailedPreconditionWhenNoCommonVersion() {
		assertThatThrownBy(() -> stub.negotiate(clientHello(2, 0, 2, 0))).isInstanceOfSatisfying(
				StatusRuntimeException.class,
				ex -> assertThat(ex.getStatus().getCode()).isEqualTo(Status.Code.FAILED_PRECONDITION));
	}

	private static ClientHello clientHello(int minMajor, int minMinor, int maxMajor, int maxMinor) {
		return ClientHello.newBuilder()
				.setClient(ComponentInfo.newBuilder().setName("SessionLayer Gateway").setSemver("0.1.0")
						.setProtocolMin(ProtocolVersions.of(minMajor, minMinor))
						.setProtocolMax(ProtocolVersions.of(maxMajor, maxMinor)).build())
				.build();
	}
}
