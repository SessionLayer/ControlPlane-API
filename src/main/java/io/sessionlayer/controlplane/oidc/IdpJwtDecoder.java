package io.sessionlayer.controlplane.oidc;

import java.util.concurrent.atomic.AtomicReference;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The shared IdP ID-token decoder (FR-AUTH-7). Built lazily from discovered
 * JWKS so an IdP that is briefly down at startup does not wedge the CP (NFR-2).
 * It enforces:
 * <ul>
 * <li>a <b>positive JWS-alg allow-list</b> (only the configured algs are
 * accepted, so {@code alg:none} and any non-allow-listed alg are
 * rejected);</li>
 * <li>signature verification against the matching JWKS key
 * (cached/rotated);</li>
 * <li>{@code iss} == the configured issuer;</li>
 * <li>{@code aud} contains the configured {@code client_id};</li>
 * <li>{@code exp}/{@code nbf} within the configured clock skew.</li>
 * </ul>
 * The ID token (not the access token) is the authentication proof.
 * {@code nonce} is checked by {@link IdTokenValidator} for the interactive flow
 * (there is no nonce on a bare bearer API call).
 */
@Component
public class IdpJwtDecoder implements ReactiveJwtDecoder {

	private final OidcMetadataService metadata;
	private final OidcProperties properties;
	private final AtomicReference<ReactiveJwtDecoder> delegate = new AtomicReference<>();

	public IdpJwtDecoder(OidcMetadataService metadata, OidcProperties properties) {
		this.metadata = metadata;
		this.properties = properties;
	}

	@Override
	public Mono<Jwt> decode(String token) {
		// Bound the discovery/JWKS fetch + verification so a hung IdP cannot leave the
		// request pending indefinitely; a timeout fails closed as an invalid token.
		return resolve().flatMap(d -> d.decode(token)).timeout(java.time.Duration.ofSeconds(15), Mono
				.error(new org.springframework.security.oauth2.jwt.BadJwtException("ID-token validation timed out")));
	}

	private Mono<ReactiveJwtDecoder> resolve() {
		ReactiveJwtDecoder cached = delegate.get();
		if (cached != null) {
			return Mono.just(cached);
		}
		return metadata.discovery().map(this::build).doOnNext(delegate::set);
	}

	private ReactiveJwtDecoder build(OidcDiscovery discovery) {
		NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(discovery.jwksUri())
				.jwsAlgorithms(algs -> properties.getAlgAllowList().forEach(a -> algs.add(SignatureAlgorithm.from(a))))
				.build();
		decoder.setJwtValidator(
				new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(properties.getClockSkew()),
						requireExpiry(), new JwtIssuerValidator(properties.getIssuer()), audience()));
		return decoder;
	}

	// OIDC Core §2: `exp` is REQUIRED (JwtTimestampValidator only checks it when
	// present).
	private OAuth2TokenValidator<Jwt> requireExpiry() {
		return jwt -> jwt.getExpiresAt() != null
				? OAuth2TokenValidatorResult.success()
				: OAuth2TokenValidatorResult
						.failure(new OAuth2Error("invalid_token", "the ID token must carry exp", null));
	}

	// OIDC Core §3.1.3.7 items 3–5: aud must contain client_id; if there are extra
	// audiences the token must carry azp == client_id (our Design §5.3 wants
	// aud==client_id).
	private OAuth2TokenValidator<Jwt> audience() {
		String clientId = properties.getClientId();
		return jwt -> {
			var aud = jwt.getAudience();
			if (aud == null || !aud.contains(clientId)) {
				return fail("the ID token audience must contain the client id");
			}
			if (aud.size() > 1 && !clientId.equals(jwt.getClaimAsString("azp"))) {
				return fail("multi-audience ID token must have azp == client id");
			}
			return OAuth2TokenValidatorResult.success();
		};
	}

	private static OAuth2TokenValidatorResult fail(String message) {
		return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", message, null));
	}
}
