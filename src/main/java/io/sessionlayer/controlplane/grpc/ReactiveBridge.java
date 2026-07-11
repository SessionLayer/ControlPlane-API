package io.sessionlayer.controlplane.grpc;

import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import reactor.core.Disposable;
import reactor.core.publisher.Mono;

/**
 * Bridges a reactive unary service result onto a gRPC {@link StreamObserver}
 * without blocking (M3). The {@link Mono} runs off the gRPC thread; a
 * server-side {@code timeout} surfaces as {@code DEADLINE_EXCEEDED} (via
 * {@link GrpcErrors}); and a client cancellation disposes the in-flight
 * subscription so a cancelled RPC does not leak its reactive work. The cancel
 * handler is registered before subscribing (through a holder) so a synchronous
 * completion can never race a "call already closed".
 */
final class ReactiveBridge {

	private ReactiveBridge() {
	}

	static <T> void forward(Mono<T> result, StreamObserver<T> observer, Duration timeout, String operation) {
		AtomicReference<Disposable> subscription = new AtomicReference<>();
		if (observer instanceof ServerCallStreamObserver<T> serverObserver) {
			serverObserver.setOnCancelHandler(() -> {
				Disposable current = subscription.get();
				if (current != null) {
					current.dispose();
				}
			});
		}
		subscription.set(result.timeout(timeout).subscribe(value -> {
			observer.onNext(value);
			observer.onCompleted();
		}, error -> observer.onError(GrpcErrors.toStatus(error, operation))));
	}
}
