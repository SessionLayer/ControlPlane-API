package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.device.DeviceFlowService;
import io.sessionlayer.controlplane.oidc.IdTokenValidator;
import io.sessionlayer.controlplane.oidc.OidcRpService;
import java.net.URI;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The CP-hosted browser OIDC pages (Design §5.2, FR-AUTH-6).
 * {@code /v1/auth/verify} is the device-flow verification page (and the plain
 * web-login entry): it starts an auth-code + PKCE login and redirects the
 * browser to the IdP. {@code /v1/auth/callback} is the redirect URI: it
 * consumes the state, validates the ID token, and — for a device flow —
 * approves the linked device flow with the approving-browser source correlation
 * (§5.2). These are server-rendered HTML / redirects (not part of the JSON API
 * contract); they are public (they establish identity) and non-leaking.
 */
@RestController
public class AuthPagesController {

	private final OidcRpService oidcRpService;
	private final DeviceFlowService deviceFlowService;

	public AuthPagesController(OidcRpService oidcRpService, DeviceFlowService deviceFlowService) {
		this.oidcRpService = oidcRpService;
		this.deviceFlowService = deviceFlowService;
	}

	@GetMapping("/v1/auth/verify")
	public Mono<ResponseEntity<String>> verify(@RequestParam(name = "user_code", required = false) String userCode,
			ServerWebExchange exchange) {
		String browserIp = sourceIp(exchange);
		if (userCode == null || userCode.isBlank()) {
			return oidcRpService.beginLogin("web_login", null, browserIp).map(AuthPagesController::redirect);
		}
		return deviceFlowService.pendingByUserCode(userCode).flatMap(
				flow -> oidcRpService.beginLogin("device", flow.id(), browserIp).map(AuthPagesController::redirect))
				.switchIfEmpty(Mono.just(html(400, page("Device approval",
						"That code is invalid or has expired. Please reconnect to get a new code."))));
	}

	@GetMapping("/v1/auth/callback")
	public Mono<ResponseEntity<String>> callback(@RequestParam(name = "code", required = false) String code,
			@RequestParam(name = "state", required = false) String state,
			@RequestParam(name = "error", required = false) String error, ServerWebExchange exchange) {
		if (error != null) {
			return Mono.just(html(400, page("Sign-in failed", "The identity provider returned an error.")));
		}
		String browserIp = sourceIp(exchange);
		return oidcRpService.handleCallback(code, state, browserIp).flatMap(result -> {
			if ("device".equals(result.purpose()) && result.deviceFlowId() != null) {
				return deviceFlowService.approve(result.deviceFlowId(), result.identity(), browserIp)
						.thenReturn(html(200, page("Approved", "You are signed in as " + escape(result.identity())
								+ ". Return to your terminal — it will continue automatically.")));
			}
			return Mono.just(html(200, page("Signed in", "You are signed in as " + escape(result.identity()) + ".")));
		}).onErrorResume(IdTokenValidator.InvalidIdToken.class,
				e -> Mono.just(html(400, page("Sign-in failed", "The sign-in could not be verified."))));
	}

	private static ResponseEntity<String> redirect(String url) {
		return ResponseEntity.status(302).location(URI.create(url)).build();
	}

	private static ResponseEntity<String> html(int status, String body) {
		return ResponseEntity.status(status).contentType(MediaType.TEXT_HTML).body(body);
	}

	private static String page(String title, String message) {
		return "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + escape(title)
				+ "</title></head><body style=\"font-family:sans-serif;max-width:32rem;margin:4rem auto\"><h1>"
				+ escape(title) + "</h1><p>" + escape(message) + "</p></body></html>";
	}

	private static String escape(String s) {
		if (s == null) {
			return "";
		}
		return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
	}

	private static String sourceIp(ServerWebExchange exchange) {
		var remote = exchange.getRequest().getRemoteAddress();
		return remote == null || remote.getAddress() == null ? null : remote.getAddress().getHostAddress();
	}
}
