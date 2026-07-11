package io.sessionlayer.controlplane.oidc;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

/**
 * Fetches and caches the IdP's {@code .well-known/openid-configuration} (Design
 * §5.3). Discovery is fetched lazily on first use and cached (a cached copy is
 * refreshed after {@code jwks-cache-ttl}) so the CP does not wedge at startup
 * if the IdP is briefly unreachable (NFR-2 degrade). A discovery whose {@code
 * issuer} does not exactly match the configured issuer is rejected (mix-up
 * defense).
 */
@Service
public class OidcMetadataService {

	private final WebClient http;
	private final OidcProperties properties;
	private final AtomicReference<Cached> cache = new AtomicReference<>();

	private record Cached(OidcDiscovery discovery, long fetchedAtMillis) {
	}

	public OidcMetadataService(WebClient.Builder httpBuilder, OidcProperties properties) {
		this.http = httpBuilder.build();
		this.properties = properties;
	}

	public Mono<OidcDiscovery> discovery() {
		Cached cached = cache.get();
		if (cached != null && !stale(cached)) {
			return Mono.just(cached.discovery());
		}
		return fetch().doOnNext(d -> cache.set(new Cached(d, System.currentTimeMillis())))
				// If a refresh fails but we hold a cached copy, keep serving it (degrade).
				.onErrorResume(err -> cached != null ? Mono.just(cached.discovery()) : Mono.error(err));
	}

	private boolean stale(Cached cached) {
		return System.currentTimeMillis() - cached.fetchedAtMillis() > properties.getJwksCacheTtl().toMillis();
	}

	private Mono<OidcDiscovery> fetch() {
		String url = properties.getIssuer().replaceAll("/+$", "") + "/.well-known/openid-configuration";
		return http.get().uri(url).retrieve().bodyToMono(JsonNode.class).timeout(Duration.ofSeconds(10)).map(node -> {
			String discoveredIssuer = text(node, "issuer");
			if (discoveredIssuer == null || !discoveredIssuer.equals(properties.getIssuer())) {
				throw new IllegalStateException("OIDC discovery issuer mismatch: expected " + properties.getIssuer()
						+ " got " + discoveredIssuer);
			}
			return new OidcDiscovery(discoveredIssuer, text(node, "authorization_endpoint"),
					text(node, "token_endpoint"), text(node, "jwks_uri"), text(node, "device_authorization_endpoint"),
					text(node, "end_session_endpoint"));
		});
	}

	private static String text(JsonNode node, String field) {
		JsonNode v = node.get(field);
		return v == null || v.isNull() ? null : v.asString();
	}
}
