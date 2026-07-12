package io.sessionlayer.controlplane.agent;

import io.sessionlayer.controlplane.agent.AgentJoinProperties.Oidc;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicReference;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Verifies an {@code OidcJoin} workload token (Design §8.1, FR-JOIN-1). Reuses
 * the S6 OIDC validation stack — the same {@link NimbusReactiveJwtDecoder} +
 * {@code DelegatingOAuth2TokenValidator} wiring as {@code IdpJwtDecoder}: a
 * <b>positive</b> JWS-alg allow-list (rejecting {@code alg:none} and any
 * non-allow-listed alg), signature verification against the issuer's JWKS,
 * {@code iss}==configured, {@code aud} contains the configured audience, and
 * {@code exp}/{@code nbf} within the configured skew ({@code exp} required). NO
 * shared secret is held (§8.1). After validation, the configured
 * {@link Oidc#getNodeClaim() node claim}'s value MUST equal the requested
 * {@code node_name}; a mismatch, an absent claim, or a disabled/misconfigured
 * verifier fails closed. All failures collapse to a generic
 * {@code UNAUTHENTICATED} (the specific cause is audited by the caller, never
 * returned — NFR-2).
 */
@Component
public class OidcJoinVerifier {

	private static final Duration DECODE_TIMEOUT = Duration.ofSeconds(15);

	private final AgentJoinProperties properties;
	private final AtomicReference<ReactiveJwtDecoder> delegate = new AtomicReference<>();

	public OidcJoinVerifier(AgentJoinProperties properties) {
		this.properties = properties;
	}

	/**
	 * Verify {@code workloadToken} authorizes {@code nodeName}; error otherwise.
	 */
	public Mono<Void> verify(String workloadToken, String nodeName) {
		Oidc oidc = properties.getOidc();
		if (!oidc.isEnabled() || oidc.getIssuer() == null || oidc.getJwksUri() == null || oidc.getAudience() == null) {
			return Mono.error(unauthenticated());
		}
		if (workloadToken == null || workloadToken.isBlank()) {
			return Mono.error(unauthenticated());
		}
		// A hung JWKS fetch fails closed as an invalid token, never a pending call.
		return decoder(oidc).decode(workloadToken)
				.timeout(DECODE_TIMEOUT, Mono.error(new BadJwtException("workload token validation timed out")))
				.onErrorMap(JwtException.class, e -> unauthenticated()).flatMap(jwt -> {
					String claim = jwt.getClaimAsString(oidc.getNodeClaim());
					if (claim == null || !constantTimeEquals(claim, nodeName)) {
						return Mono.error(unauthenticated());
					}
					return Mono.empty();
				});
	}

	private ReactiveJwtDecoder decoder(Oidc oidc) {
		ReactiveJwtDecoder cached = delegate.get();
		if (cached != null) {
			return cached;
		}
		NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(oidc.getJwksUri())
				.jwsAlgorithms(algs -> oidc.getAllowedAlgs().forEach(a -> algs.add(SignatureAlgorithm.from(a))))
				.build();
		decoder.setJwtValidator(jwtValidator(oidc));
		delegate.set(decoder);
		return decoder;
	}

	/**
	 * The iss/aud/exp/nbf validator chain — identical to {@code IdpJwtDecoder},
	 * over the agent-join issuer/audience. Package-visible so the unit test builds
	 * the exact same gates over a controllable key.
	 */
	static OAuth2TokenValidator<Jwt> jwtValidator(Oidc oidc) {
		return new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(oidc.getClockSkew()), requireExpiry(),
				new JwtIssuerValidator(oidc.getIssuer()), audience(oidc.getAudience()));
	}

	private static OAuth2TokenValidator<Jwt> requireExpiry() {
		return jwt -> jwt.getExpiresAt() != null
				? OAuth2TokenValidatorResult.success()
				: OAuth2TokenValidatorResult
						.failure(new OAuth2Error("invalid_token", "the workload token must carry exp", null));
	}

	private static OAuth2TokenValidator<Jwt> audience(String audience) {
		return jwt -> {
			var aud = jwt.getAudience();
			return aud != null && aud.contains(audience)
					? OAuth2TokenValidatorResult.success()
					: OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token",
							"the workload token audience must contain " + "the agent-join audience", null));
		};
	}

	private static boolean constantTimeEquals(String a, String b) {
		return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
	}

	private static AgentJoinException unauthenticated() {
		return new AgentJoinException(AgentJoinException.Reason.UNAUTHENTICATED, "enrollment refused");
	}
}
