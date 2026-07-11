package io.sessionlayer.controlplane.oidc;

import java.util.ArrayList;
import java.util.List;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Validates an OIDC ID token and resolves it to a {@link ResolvedIdentity}
 * (FR-AUTH-7/8). Delegates signature + {@code iss}/{@code aud}/{@code exp}/
 * {@code alg}-allow-list checks to {@link IdpJwtDecoder}, then — for the
 * interactive auth-code flow — checks {@code nonce} against the value bound
 * into the request, and maps claims/groups to the resolved identity
 * server-side. Any validation failure fails closed (empty {@link Mono} error) —
 * never a fallback to a weaker proof.
 */
@Component
public class IdTokenValidator {

	private final IdpJwtDecoder decoder;
	private final OidcProperties properties;

	public IdTokenValidator(IdpJwtDecoder decoder, OidcProperties properties) {
		this.decoder = decoder;
		this.properties = properties;
	}

	/** Signals a rejected ID token (a fail-closed authentication failure). */
	public static final class InvalidIdToken extends RuntimeException {
		public InvalidIdToken(String message) {
			super(message);
		}
	}

	/**
	 * Validate a raw ID token. When {@code expectedNonce} is non-null the token's
	 * {@code nonce} claim must equal it (interactive flow replay protection); pass
	 * {@code null} for the bearer-API path (no interactive nonce).
	 */
	public Mono<ResolvedIdentity> validate(String idToken, String expectedNonce) {
		return decoder.decode(idToken).onErrorMap(JwtException.class, e -> new InvalidIdToken(e.getMessage()))
				.map(jwt -> {
					if (expectedNonce != null) {
						String nonce = jwt.getClaimAsString("nonce");
						if (nonce == null || !constantTimeEquals(nonce, expectedNonce)) {
							throw new InvalidIdToken("nonce mismatch");
						}
					}
					return resolve(jwt);
				});
	}

	/** Resolve identity + groups from an already-validated JWT (FR-AUTH-8). */
	public ResolvedIdentity resolve(Jwt jwt) {
		String identity = jwt.getClaimAsString(properties.getIdentityClaim());
		if (identity == null || identity.isBlank()) {
			identity = jwt.getSubject();
		}
		if (identity == null || identity.isBlank()) {
			throw new InvalidIdToken("no resolvable identity claim");
		}
		return new ResolvedIdentity(identity, extractGroups(jwt), jwt.getSubject());
	}

	private List<String> extractGroups(Jwt jwt) {
		Object raw = jwt.getClaims().get(properties.getGroupsClaim());
		List<String> groups = new ArrayList<>();
		if (raw instanceof List<?> list) {
			list.forEach(v -> {
				if (v != null) {
					groups.add(v.toString());
				}
			});
		} else if (raw instanceof String s && !s.isBlank()) {
			for (String g : s.split("[\\s,]+")) {
				if (!g.isBlank()) {
					groups.add(g);
				}
			}
		}
		return List.copyOf(groups);
	}

	private static boolean constantTimeEquals(String a, String b) {
		return java.security.MessageDigest.isEqual(a.getBytes(java.nio.charset.StandardCharsets.UTF_8),
				b.getBytes(java.nio.charset.StandardCharsets.UTF_8));
	}
}
