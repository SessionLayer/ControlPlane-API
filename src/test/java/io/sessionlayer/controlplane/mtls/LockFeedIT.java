package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.grpc.ManagedChannel;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.grpc.LockFeedHub;
import io.sessionlayer.controlplane.grpc.v1.LockEvent;
import io.sessionlayer.controlplane.grpc.v1.LockFeedGrpc;
import io.sessionlayer.controlplane.grpc.v1.LockSnapshot;
import io.sessionlayer.controlplane.grpc.v1.StreamLocksRequest;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Part C — the actively-pushed lock deny-list stream over mTLS (FR-CHAN-3,
 * FR-LOCK-2). Proves the initial authoritative snapshot, live add/remove
 * deltas, periodic heartbeats, a full RESYNC on reconnect, and the
 * no-lost-event ordering (a lock created around subscribe time is never
 * dropped).
 */
class LockFeedIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final Duration TIMEOUT = Duration.ofSeconds(10);

	@DynamicPropertySource
	static void fastHeartbeat(DynamicPropertyRegistry registry) {
		registry.add("sessionlayer.locks.heartbeat-interval", () -> "PT0.2S");
	}

	@Autowired
	private AccessLockRepository accessLocks;
	@Autowired
	private LockFeedHub lockFeedHub;

	@Test
	void snapshotThenLiveAddAndRemove() {
		EnrolledGateway gateway = enroll("gw-feed-" + unique());
		try (LockStream stream = openStream(gateway)) {
			assertThat(stream.awaitSnapshot()).isNotNull();

			String identity = "locked-" + unique();
			AccessLock lock = publishLock(identityTarget(identity), "incident-" + unique());
			LockEvent added = stream.awaitAdded(lock.id());
			assertThat(added.getAdded().getTarget().getIdentitiesList()).containsExactly(identity);
			assertThat(added.getAdded().getReason()).startsWith("incident-");

			removeLock(lock.id());
			LockEvent removed = stream.awaitRemoved(lock.id());
			assertThat(removed.getRemoved().getLockId()).isEqualTo(lock.id().toString());
		}
	}

	// F-lockfeed-caller-gate-1 (A3): a locked/de-authorized Gateway's still-valid
	// cert
	// must NOT be able to stream the fleet deny-list (which
	// identities/nodes/principals
	// are locked). It is refused with a generic PERMISSION_DENIED before any
	// snapshot.
	@Test
	void aLockedCallerGatewayIsRefusedTheLockFeedWithNoSnapshot() throws Exception {
		EnrolledGateway gateway = enroll("gw-feed-locked-" + unique());
		db.sql("UPDATE runtime.gateway_identity SET status = 'locked' WHERE id = :id").bind("id", gateway.gatewayId())
				.fetch().rowsUpdated().block();

		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		BlockingQueue<LockEvent> events = new LinkedBlockingQueue<>();
		java.util.concurrent.CompletableFuture<Throwable> error = new java.util.concurrent.CompletableFuture<>();
		try {
			LockFeedGrpc.newStub(channel).streamLocks(StreamLocksRequest.newBuilder().build(), new StreamObserver<>() {
				@Override
				public void onNext(LockEvent event) {
					events.add(event);
				}

				@Override
				public void onError(Throwable t) {
					error.complete(t);
				}

				@Override
				public void onCompleted() {
					error.complete(new IllegalStateException("stream completed without an error"));
				}
			});
			Throwable t = error.get(10, TimeUnit.SECONDS);
			assertThat(io.grpc.Status.fromThrowable(t).getCode()).isEqualTo(io.grpc.Status.Code.PERMISSION_DENIED);
			assertThat(events).noneMatch(LockEvent::hasSnapshot);
		} finally {
			channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
		}
	}

	@Test
	void heartbeatsKeepTheStreamAlive() {
		EnrolledGateway gateway = enroll("gw-hb-" + unique());
		try (LockStream stream = openStream(gateway)) {
			stream.awaitSnapshot();
			LockEvent heartbeat = stream.awaitHeartbeat();
			assertThat(heartbeat.getHeartbeat().getSentAtEpochSeconds()).isPositive();
		}
	}

	@Test
	void aReconnectResyncsTheFullCurrentSet() {
		EnrolledGateway gateway = enroll("gw-resync-" + unique());
		// A lock created while a Gateway is disconnected must appear in the NEXT
		// connection's snapshot (the resync primitive), even though no live delta
		// reached it.
		try (LockStream first = openStream(gateway)) {
			first.awaitSnapshot();
		}
		AccessLock offline = publishLock(identityTarget("offline-" + unique()), "created-while-disconnected");
		try (LockStream second = openStream(gateway)) {
			LockSnapshot snapshot = second.awaitSnapshot();
			assertThat(lockIds(snapshot)).contains(offline.id().toString());
		}
	}

	@Test
	void aLockPushedAfterAllGatewaysDisconnectStillReachesAReconnectedGateway() {
		// The zero-subscriber fail-open guard: the hub MUST survive an all-disconnected
		// blip (autoCancel=false). On the old autoCancel=true sink the hub terminated
		// the
		// instant subscribers hit 0, and a reconnecting Gateway then saw only snapshot
		// +
		// heartbeats — never a live delta — while looking healthy (a silent fail-open).
		EnrolledGateway gateway = enroll("gw-blip-" + unique());
		try (LockStream first = openStream(gateway)) {
			first.awaitSnapshot();
			awaitSubscribers(1);
		}
		awaitSubscribers(0); // the window that killed an autoCancel=true hub

		// A NEW connection, then a lock created AFTER its snapshot: it can only arrive
		// as
		// a LIVE added delta through the (surviving) hub — never via that snapshot.
		try (LockStream second = openStream(gateway)) {
			second.awaitSnapshot();
			AccessLock afterBlip = publishLock(identityTarget("post-blip-" + unique()), "created-after-blip");
			LockEvent added = second.awaitAdded(afterBlip.id());
			assertThat(added.getAdded().getLockId()).isEqualTo(afterBlip.id().toString());
		}
	}

	@Test
	void aLockCreatedAroundSubscribeTimeIsNeverLost() {
		EnrolledGateway gateway = enroll("gw-race-" + unique());
		try (LockStream stream = openStream(gateway)) {
			// Publish right after opening, racing the snapshot read: the lock must arrive
			// either inside the snapshot or as a buffered add — never dropped.
			AccessLock racing = publishLock(identityTarget("race-" + unique()), "racing-create");
			Set<String> seen = stream.collectLockIds(Duration.ofSeconds(5));
			assertThat(seen).contains(racing.id().toString());
		}
	}

	// ---- helpers -----------------------------------------------------------

	private AccessLock publishLock(ObjectNode selector, String reason) {
		AccessLock saved = accessLocks.save(AccessLock.create(selector, "strict", null, null, reason, "tester"))
				.block();
		lockFeedHub.publishAdded(saved);
		return saved;
	}

	private void removeLock(UUID id) {
		accessLocks.deleteById(id).block();
		lockFeedHub.publishRemoved(id);
	}

	// Server-side stream cancellation propagates asynchronously after a client
	// channel
	// closes; poll the hub's connected-stream gauge until it settles (bounded).
	private void awaitSubscribers(int expected) {
		long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
		while (System.nanoTime() < deadline && lockFeedHub.currentSubscribers() != expected) {
			try {
				Thread.sleep(20);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				break;
			}
		}
		assertThat(lockFeedHub.currentSubscribers()).isEqualTo(expected);
	}

	private static ObjectNode identityTarget(String identity) {
		ObjectNode selector = JSON.objectNode();
		selector.set("identities", JSON.arrayNode().add(identity));
		return selector;
	}

	private static Set<String> lockIds(LockSnapshot snapshot) {
		Set<String> ids = new HashSet<>();
		snapshot.getLocksList().forEach(lock -> ids.add(lock.getLockId()));
		return ids;
	}

	private LockStream openStream(EnrolledGateway gateway) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		BlockingQueue<LockEvent> events = new LinkedBlockingQueue<>();
		LockFeedGrpc.newStub(channel).streamLocks(StreamLocksRequest.newBuilder().build(), new StreamObserver<>() {
			@Override
			public void onNext(LockEvent event) {
				events.add(event);
			}

			@Override
			public void onError(Throwable error) {
				// Channel shutdown surfaces as CANCELLED; the test asserts on delivered events.
			}

			@Override
			public void onCompleted() {
			}
		});
		return new LockStream(channel, events);
	}

	/**
	 * A live StreamLocks subscription: polls delivered events, skipping heartbeats.
	 */
	private static final class LockStream implements AutoCloseable {

		private final ManagedChannel channel;
		private final BlockingQueue<LockEvent> events;

		LockStream(ManagedChannel channel, BlockingQueue<LockEvent> events) {
			this.channel = channel;
			this.events = events;
		}

		LockSnapshot awaitSnapshot() {
			return await(LockEvent::hasSnapshot).getSnapshot();
		}

		LockEvent awaitHeartbeat() {
			return await(LockEvent::hasHeartbeat);
		}

		LockEvent awaitAdded(UUID lockId) {
			return await(e -> e.hasAdded() && e.getAdded().getLockId().equals(lockId.toString()));
		}

		LockEvent awaitRemoved(UUID lockId) {
			return await(e -> e.hasRemoved() && e.getRemoved().getLockId().equals(lockId.toString()));
		}

		/** Every lock id seen (snapshot members + adds) within the window. */
		Set<String> collectLockIds(Duration window) {
			Set<String> ids = new HashSet<>();
			long deadline = System.nanoTime() + window.toNanos();
			while (System.nanoTime() < deadline) {
				LockEvent event = poll(Duration.ofMillis(200));
				if (event == null) {
					continue;
				}
				if (event.hasSnapshot()) {
					event.getSnapshot().getLocksList().forEach(lock -> ids.add(lock.getLockId()));
				} else if (event.hasAdded()) {
					ids.add(event.getAdded().getLockId());
				}
			}
			return ids;
		}

		private LockEvent await(java.util.function.Predicate<LockEvent> predicate) {
			long deadline = System.nanoTime() + TIMEOUT.toNanos();
			while (System.nanoTime() < deadline) {
				LockEvent event = poll(Duration.ofMillis(500));
				if (event != null && predicate.test(event)) {
					return event;
				}
			}
			throw new AssertionError("expected lock event did not arrive within " + TIMEOUT);
		}

		private LockEvent poll(Duration timeout) {
			try {
				return events.poll(timeout.toMillis(), TimeUnit.MILLISECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				return null;
			}
		}

		@Override
		public void close() {
			try {
				channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
