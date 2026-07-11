package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.oidc.IdpJwtDecoder;
import io.sessionlayer.controlplane.oidc.OidcProperties;
import io.sessionlayer.controlplane.pin.PinService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * OIDC back-channel logout (FR-AUTH-11, deferred behind this hook per §17). The
 * IdP posts a signed {@code logout_token}; on a valid token the CP revokes the
 * subject's pins (an authN shortcut must not outlive the session it stood in
 * for). Public (authenticated by the token signature). Best-effort subject→
 * identity mapping; full session-index handling is future work.
 */
@RestController
public class BackchannelLogoutController {

	private final IdpJwtDecoder idpJwtDecoder;
	private final OidcProperties oidcProperties;
	private final PinService pinService;

	public BackchannelLogoutController(IdpJwtDecoder idpJwtDecoder, OidcProperties oidcProperties,
			PinService pinService) {
		this.idpJwtDecoder = idpJwtDecoder;
		this.oidcProperties = oidcProperties;
		this.pinService = pinService;
	}

	@PostMapping("/v1/auth/backchannel-logout")
	public Mono<ResponseEntity<Void>> logout(
			@RequestParam(name = "logout_token", required = false) String logoutToken) {
		if (logoutToken == null || logoutToken.isBlank()) {
			return Mono.just(ResponseEntity.badRequest().build());
		}
		return idpJwtDecoder.decode(logoutToken).flatMap(jwt -> {
			String identity = identityOf(jwt);
			if (identity == null) {
				return Mono.just(ResponseEntity.badRequest().<Void>build());
			}
			return pinService.revokeForIdentity(identity, "oidc-idp", "backchannel_logout")
					.thenReturn(ResponseEntity.ok().<Void>build());
		}).onErrorResume(e -> Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).build()));
	}

	private String identityOf(Jwt jwt) {
		String claimed = jwt.getClaimAsString(oidcProperties.getIdentityClaim());
		return claimed != null && !claimed.isBlank() ? claimed : jwt.getSubject();
	}
}
