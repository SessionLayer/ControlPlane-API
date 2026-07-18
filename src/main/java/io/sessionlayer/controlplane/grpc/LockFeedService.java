package io.sessionlayer.controlplane.grpc;

import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.authz.LockFeedProperties;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.gateway.GatewayRequestException;
import io.sessionlayer.controlplane.grpc.v1.Heartbeat;
import io.sessionlayer.controlplane.grpc.v1.LockEvent;
import io.sessionlayer.controlplane.grpc.v1.LockFeedGrpc;
import io.sessionlayer.controlplane.grpc.v1.StreamLocksRequest;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
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
	private final GatewayIdentityRepository gatewayIdentities;

	public LockFeedService(LockFeedHub hub, LockFeedProperties properties,
			GatewayIdentityRepository gatewayIdentities) {
		this.hub = hub;
		this.properties = properties;
		this.gatewayIdentities = gatewayIdentities;
	}

	@Override
	public void streamLocks(StreamLocksRequest request, StreamObserver<LockEvent> observer) {
		MtlsPeer peer = MtlsContext.peer();
		ServerCallStreamObserver<LockEvent> server = (ServerCallStreamObserver<LockEvent>) observer;
		UUID callerGatewayId = peer == null ? null : peer.gatewayId();
		String presentedFingerprint = (peer == null || peer.certificate() == null)
				? null
				: CertificateFingerprints.sha256Hex(peer.certificate());

		// F-lockfeed-caller-gate-1 (A3): the whole-fleet deny-list is sensitive recon
		// (which identities/nodes/principals are currently locked). Gate the stream on
		// the caller Gateway being ACTIVE with a pinned fingerprint — the same check
		// the
		// sign paths enforce — so a locked/superseded-cert Gateway (or any agent)
		// cannot
		// read it. Rejection surfaces as a generic PERMISSION_DENIED before any
		// snapshot.
		Flux<LockEvent> stream = requireActiveGateway(callerGatewayId, presentedFingerprint)
				.flatMapMany(gw -> lockStream(gw.id()));
		ServerStreamBridge.forward(stream, server, "StreamLocks");
	}

	// The caller Gateway must be ACTIVE and present a cert pinned to its current or
	// previous fingerprint; else a generic PERMISSION_DENIED (fail closed). Agent
	// peers
	// (gatewayId == null) are refused — the lock feed is a Gateway-only surface.
	private Mono<GatewayIdentity> requireActiveGateway(UUID callerGatewayId, String presentedFingerprint) {
		if (callerGatewayId == null || presentedFingerprint == null) {
			return Mono.error(denied());
		}
		return gatewayIdentities.findById(callerGatewayId).switchIfEmpty(Mono.error(denied())).flatMap(gw -> {
			boolean active = "active".equals(gw.status());
			boolean pinned = presentedFingerprint.equals(gw.fingerprint())
					|| presentedFingerprint.equals(gw.prevFingerprint());
			return active && pinned ? Mono.just(gw) : Mono.error(denied());
		});
	}

	private static GatewayRequestException denied() {
		return new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED, "lock feed refused");
	}

	private Flux<LockEvent> lockStream(UUID gatewayId) {
		LOG.debug("lock feed opened for gateway {}", gatewayId);
		return Flux.defer(() -> {
			// Subscribe to the live multicast BEFORE reading the snapshot: a lock created
			// during the snapshot read lands in this per-connection buffer and is emitted
			// right after the snapshot, so no add is ever lost (the Gateway dedups by
			// lock_id). The buffer is BOUNDED — an overflow (a stalled Gateway) fails the
			// stream, forcing a reconnect + full resync rather than a silently-dropped
			// deny.
			Sinks.Many<LockEvent> buffer = Sinks.many().unicast()
					.onBackpressureBuffer(Queues.<LockEvent>get(properties.getStreamBufferCapacity()).get());
			// Fail the client stream if the shared hub ever terminates — on error OR on
			// an unexpected onComplete. Coasting on heartbeats after the delta source died
			// would look healthy while silently missing every new lock (fail OPEN); instead
			// we break the stream so the Gateway reconnects and does a full snapshot RESYNC
			// (fail CLOSED). Normal per-connection teardown disposes the pump (a cancel,
			// not
			// a completion), so this never fires on a routine disconnect.
			Disposable pump = hub.liveEvents().subscribe(event -> bufferEmit(buffer, event), buffer::tryEmitError,
					() -> buffer.tryEmitError(new IllegalStateException("lock feed source terminated")));
			Flux<LockEvent> heartbeats = Flux.interval(properties.getHeartbeatInterval()).map(tick -> heartbeat());
			return hub.snapshotEvent().concatWith(Flux.merge(buffer.asFlux(), heartbeats))
					.doFinally(signal -> pump.dispose());
		});
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
