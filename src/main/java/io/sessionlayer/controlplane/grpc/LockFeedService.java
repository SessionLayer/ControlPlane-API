package io.sessionlayer.controlplane.grpc;

import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.authz.LockFeedProperties;
import io.sessionlayer.controlplane.grpc.v1.Heartbeat;
import io.sessionlayer.controlplane.grpc.v1.LockEvent;
import io.sessionlayer.controlplane.grpc.v1.LockFeedGrpc;
import io.sessionlayer.controlplane.grpc.v1.StreamLocksRequest;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;
import reactor.util.concurrent.Queues;

/**
 * The CP→Gateway actively-pushed lock deny-list stream (Design §6.3/§8.3/§8.4;
 * FR-CHAN-3, FR-LOCK-2). On subscribe the Gateway receives one authoritative
 * {@code LockSnapshot} (a full RESYNC), then live add/remove deltas from the
 * shared {@link LockFeedHub} interleaved with periodic heartbeats.
 *
 * <p>
 * mTLS/gateway-identity tier: the
 * {@link io.sessionlayer.controlplane.grpc.AuthInterceptor} has already
 * authenticated the caller from its client certificate; the peer is resolved
 * here for diagnostics only (the whole fleet-wide lock set goes to every
 * Gateway, which matches locally against its signed decision contexts — the CP
 * does no per-Gateway filtering).
 */
@Service
public class LockFeedService extends LockFeedGrpc.LockFeedImplBase {

	private static final Logger LOG = LoggerFactory.getLogger(LockFeedService.class);

	private final LockFeedHub hub;
	private final LockFeedProperties properties;

	public LockFeedService(LockFeedHub hub, LockFeedProperties properties) {
		this.hub = hub;
		this.properties = properties;
	}

	@Override
	public void streamLocks(StreamLocksRequest request, StreamObserver<LockEvent> observer) {
		MtlsPeer peer = MtlsContext.peer();
		LOG.debug("lock feed opened for gateway {}", peer.gatewayId());
		ServerCallStreamObserver<LockEvent> server = (ServerCallStreamObserver<LockEvent>) observer;

		Flux<LockEvent> stream = Flux.defer(() -> {
			// Subscribe to the live multicast BEFORE reading the snapshot: a lock created
			// during the snapshot read lands in this per-connection buffer and is emitted
			// right after the snapshot, so no add is ever lost (the Gateway dedups by
			// lock_id). The buffer is BOUNDED — an overflow (a stalled Gateway) fails the
			// stream, forcing a reconnect + full resync rather than a silently-dropped
			// deny.
			Sinks.Many<LockEvent> buffer = Sinks.many().unicast()
					.onBackpressureBuffer(Queues.<LockEvent>get(properties.getStreamBufferCapacity()).get());
			Disposable pump = hub.liveEvents().subscribe(event -> bufferEmit(buffer, event), buffer::tryEmitError);
			Flux<LockEvent> heartbeats = Flux.interval(properties.getHeartbeatInterval()).map(tick -> heartbeat());
			return hub.snapshotEvent().concatWith(Flux.merge(buffer.asFlux(), heartbeats))
					.doFinally(signal -> pump.dispose());
		});
		ServerStreamBridge.forward(stream, server, "StreamLocks");
	}

	private static void bufferEmit(Sinks.Many<LockEvent> buffer, LockEvent event) {
		if (buffer.tryEmitNext(event).isFailure()) {
			buffer.tryEmitError(new IllegalStateException("lock feed backpressure buffer overflow"));
		}
	}

	private static LockEvent heartbeat() {
		return LockEvent.newBuilder()
				.setHeartbeat(Heartbeat.newBuilder().setSentAtEpochSeconds(Instant.now().getEpochSecond()).build())
				.build();
	}
}
