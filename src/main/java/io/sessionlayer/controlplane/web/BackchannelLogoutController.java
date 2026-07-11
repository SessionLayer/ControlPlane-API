package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.auth.AuthProperties;
import io.sessionlayer.controlplane.auth.RateLimiter;
import io.sessionlayer.controlplane.oidc.IdpJwtDecoder;
import io.sessionlayer.controlplane.oidc.OidcProperties;
import io.sessionlayer.controlplane.pin.PinService;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * OIDC back-channel logout (FR-AUTH-11, deferred behind this hook per §17). The
 * IdP posts a signed {@code logout_token}; on a valid <b>logout</b> token the
 * CP revokes the subject's pins (an authN shortcut must not outlive the session
 * it stood in for). Validates the logout-token profile (OIDC BCL 1.0 §2.6): the
 * {@code events} claim MUST carry the backchannel-logout event, a {@code nonce}
 * MUST be absent (this is what distinguishes a logout token from an ID token,
 * so a plain ID token cannot be replayed here), and {@code sub}/{@code sid}
 * present. Public (authenticated by the token signature) and rate-limited per
 * source.
 */
@RestController
public class BackchannelLogoutController {

	private static final String LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

	private final IdpJwtDecoder idpJwtDecoder;
	private final OidcProperties oidcProperties;
	private final PinService pinService;
	private final RateLimiter rateLimiter;
	private final AuthProperties authProperties;

	public BackchannelLogoutController(IdpJwtDecoder idpJwtDecoder, OidcProperties oidcProperties,
			PinService pinService, RateLimiter rateLimiter, AuthProperties authProperties) {
		this.idpJwtDecoder = idpJwtDecoder;
		this.oidcProperties = oidcProperties;
		this.pinService = pinService;
		this.rateLimiter = rateLimiter;
		this.authProperties = authProperties;
	}

	@PostMapping("/v1/auth/backchannel-logout")
	public Mono<ResponseEntity<Void>> logout(@RequestParam(name = "logout_token", required = false) String logoutToken,
			ServerWebExchange exchange) {
		if (logoutToken == null || logoutToken.isBlank()) {
			return Mono.just(ResponseEntity.badRequest().build());
		}
		String ip = sourceIp(exchange);
		return rateLimiter.tryAcquire("bcl:" + ip, authProperties.getTokenEndpoint()).flatMap(allowed -> {
			if (!allowed) {
				return Mono.just(ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).<Void>build());
			}
			return idpJwtDecoder.decode(logoutToken).flatMap(jwt -> {
				if (!isLogoutToken(jwt)) {
					return Mono.just(ResponseEntity.badRequest().<Void>build());
				}
				String identity = identityOf(jwt);
				if (identity == null) {
					return Mono.just(ResponseEntity.badRequest().<Void>build());
				}
				return pinService.revokeForIdentity(identity, "oidc-idp", "backchannel_logout")
						.thenReturn(ResponseEntity.ok().<Void>build());
			}).onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).build()));
		});
	}

	// OIDC BCL 1.0 §2.6: an ID token carries a nonce; a logout token MUST NOT, MUST
	// carry the backchannel-logout event, and MUST identify a subject/session.
	private static boolean isLogoutToken(Jwt jwt) {
		if (jwt.getClaimAsString("nonce") != null) {
			return false;
		}
		Object events = jwt.getClaim("events");
		boolean hasLogoutEvent = events instanceof Map<?, ?> map && map.containsKey(LOGOUT_EVENT);
		boolean hasSubjectOrSession = jwt.getSubject() != null || jwt.getClaimAsString("sid") != null;
		return hasLogoutEvent && hasSubjectOrSession;
	}

	private String identityOf(Jwt jwt) {
		String claimed = jwt.getClaimAsString(oidcProperties.getIdentityClaim());
		return claimed != null && !claimed.isBlank() ? claimed : jwt.getSubject();
	}

	private static String sourceIp(ServerWebExchange exchange) {
		var remote = exchange.getRequest().getRemoteAddress();
		return remote == null || remote.getAddress() == null ? "" : remote.getAddress().getHostAddress();
	}
}
