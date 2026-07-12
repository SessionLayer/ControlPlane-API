package io.sessionlayer.controlplane.grpc;

import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.grpc.v1.LockEvent;
import io.sessionlayer.controlplane.grpc.v1.LockRemoval;
import io.sessionlayer.controlplane.grpc.v1.LockSnapshot;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.util.concurrent.Queues;

/**
 * The CP-side fan-out for the actively-pushed lock deny-list (§8.3/§8.4;
 * FR-CHAN-3, FR-LOCK-2). The lock CRUD publishes add/remove deltas here; every
 * connected {@link LockFeedService} stream multicasts them to its Gateway. A
 * delta is best-effort — a Gateway that misses one self-heals via the full
 * snapshot RESYNC it receives on reconnect, and it enforces expiry locally, so
 * the safety spine never depends on this hop succeeding.
 */
@Component
public class LockFeedHub {

	private static final Logger LOG = LoggerFactory.getLogger(LockFeedHub.class);

	private final AccessLockRepository locks;
	// autoCancel=FALSE is load-bearing (the safety spine): the default
	// onBackpressureBuffer() auto-cancels the sink the instant the
	// connected-Gateway
	// count hits 0 (a single-Gateway redeploy, a rolling restart, a
	// maxConnectionAge
	// rotation — any all-disconnected blip), which would terminate the hub for the
	// whole process. Reconnecting Gateways would then get snapshot + heartbeats but
	// NEVER a live delta, looking healthy while the deny channel is silently open.
	// We
	// keep the hub alive across zero-subscriber windows; a reconnecting Gateway's
	// snapshot covers the gap, and future deltas flow again.
	private final Sinks.Many<LockEvent> sink = Sinks.many().multicast().onBackpressureBuffer(Queues.SMALL_BUFFER_SIZE,
			false);

	// Per-process, constant for the CP's lifetime: a restart yields a different
	// value, letting a Gateway notice the feed/CP restarted (advisory only; NOT the
	// policy epoch). Seeded from wall-clock ms for human-meaningful ordering.
	private final long feedEpoch = System.currentTimeMillis();

	public LockFeedHub(AccessLockRepository locks) {
		this.locks = locks;
	}

	public void publishAdded(AccessLock lock) {
		emit(LockEvent.newBuilder().setAdded(LockCodec.toProto(lock)).build());
	}

	public void publishRemoved(UUID lockId) {
		emit(LockEvent.newBuilder().setRemoved(LockRemoval.newBuilder().setLockId(lockId.toString()).build()).build());
	}

	/** The live add/remove multicast; a per-connection stream subscribes to it. */
	Flux<LockEvent> liveEvents() {
		return sink.asFlux();
	}

	/** How many Gateway streams are currently attached to the live feed. */
	public int currentSubscribers() {
		return sink.currentSubscriberCount();
	}

	/**
	 * The authoritative current lock set (all UNEXPIRED locks), read at call time —
	 * the RESYNC primitive a Gateway receives on connect/reconnect.
	 */
	Mono<LockEvent> snapshotEvent() {
		Instant now = Instant.now();
		return locks.findAll().filter(lock -> unexpired(lock, now)).map(LockCodec::toProto).collectList()
				.map(list -> LockEvent.newBuilder()
						.setSnapshot(LockSnapshot.newBuilder().addAllLocks(list).setFeedEpoch(feedEpoch).build())
						.build());
	}

	private static boolean unexpired(AccessLock lock, Instant now) {
		return lock.expiresAt() == null || lock.expiresAt().isAfter(now);
	}

	// Fan-out is best-effort and must never block or fail the (already committed)
	// CRUD request path. Serialize access (Sinks are single-writer). A non-OK
	// result
	// is diagnostic only: a zero-subscriber drop is covered by the connect-time
	// snapshot, and a genuine terminal failure breaks each per-connection stream
	// (LockFeedService fails the buffer on hub onError/onComplete) so the Gateway
	// reconnects and RESYNCs — this WARN does not by itself trigger a resync.
	private void emit(LockEvent event) {
		Sinks.EmitResult result;
		synchronized (sink) {
			result = sink.tryEmitNext(event);
		}
		if (result.isFailure()) {
			LOG.warn("lock feed hub emit returned {} — delta not fanned out to currently-connected streams", result);
		}
	}
}
