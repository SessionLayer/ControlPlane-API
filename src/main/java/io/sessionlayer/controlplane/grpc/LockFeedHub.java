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
	private final Sinks.Many<LockEvent> sink = Sinks.many().multicast().onBackpressureBuffer();

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
	// CRUD request path. Serialize access (Sinks are single-writer) and
	// drop-with-a-
	// warning on failure — the Gateway resyncs on reconnect, so no deny is lost.
	private void emit(LockEvent event) {
		Sinks.EmitResult result;
		synchronized (sink) {
			result = sink.tryEmitNext(event);
		}
		if (result.isFailure()) {
			LOG.warn("lock feed emit dropped ({}); Gateways will resync the full set on reconnect", result);
		}
	}
}
