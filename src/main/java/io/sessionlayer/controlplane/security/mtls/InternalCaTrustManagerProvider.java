package io.sessionlayer.controlplane.security.mtls;

import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.X509TrustManager;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Supplies (and caches, refresh-ahead) the {@link X509TrustManager} for the
 * internal mTLS CA — the trust anchor for REST mTLS client certificates
 * (FR-AUTH-17), the same anchor the gRPC plane's {@code AuthInterceptor} uses.
 * The CA cert is loaded from the DB and cached for a short TTL so a per-request
 * validation is not a DB round-trip; a reload failure keeps serving the cached
 * anchor (the CA rotates rarely; a transient DB blip must not open a hole).
 */
@Component
public class InternalCaTrustManagerProvider {

	private static final Duration CACHE_TTL = Duration.ofMinutes(5);

	private final InternalMtlsCaService mtlsCa;
	private final AtomicReference<Cached> cache = new AtomicReference<>();

	private record Cached(X509TrustManager trustManager, long loadedAtMillis) {
	}

	public InternalCaTrustManagerProvider(InternalMtlsCaService mtlsCa) {
		this.mtlsCa = mtlsCa;
	}

	public Mono<X509TrustManager> trustManager() {
		Cached cached = cache.get();
		if (cached != null && System.currentTimeMillis() - cached.loadedAtMillis() < CACHE_TTL.toMillis()) {
			return Mono.just(cached.trustManager());
		}
		return mtlsCa.activeBackend()
				.flatMap(backend -> Mono.fromCallable(() -> X509Certificates.trustManagerFor(backend.caCertificate()))
						.subscribeOn(Schedulers.boundedElastic()))
				.map(tm -> {
					cache.set(new Cached(tm, System.currentTimeMillis()));
					return tm;
				}).onErrorResume(err -> cached != null ? Mono.just(cached.trustManager()) : Mono.error(err));
	}
}
