package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.authz.Cidrs;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * The discouraged HTTP Basic escape hatch (FR-AUTH-17), added to the chain only
 * when {@code sessionlayer.rest-security.basic-auth.enabled=true}. It is a
 * deny-only, fail-closed control: a Basic credential authenticates <b>only</b>
 * from an allow-listed source CIDR and only for the single configured operator
 * (password compared against a BCrypt hash, off the event loop). A missing/bad
 * credential or a disallowed source does not authenticate here — the request
 * falls through and is denied by the authorization filter if nothing else
 * proved it. Basic is never the primary path; a startup warning is emitted.
 */
final class BasicEscapeHatchFilter implements WebFilter {

	private final SecurityProperties.BasicAuth config;
	private final PasswordEncoder passwordEncoder;

	BasicEscapeHatchFilter(SecurityProperties.BasicAuth config, PasswordEncoder passwordEncoder) {
		this.config = config;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		String header = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if (header == null || !header.regionMatches(true, 0, "Basic ", 0, 6)) {
			return chain.filter(exchange);
		}
		if (!sourceAllowed(exchange) || config.getUsername() == null || config.getPasswordHash() == null) {
			return chain.filter(exchange);
		}
		String[] creds = decode(header.substring(6));
		if (creds == null) {
			return chain.filter(exchange);
		}
		String user = creds[0];
		String password = creds[1];
		return Mono.fromCallable(() -> {
			// Evaluate both factors (no short-circuit) and compare the username in
			// constant time — avoid a username-existence timing oracle.
			boolean userOk = io.sessionlayer.controlplane.auth.Secrets.constantTimeEquals(user, config.getUsername());
			boolean passwordOk = passwordEncoder.matches(password, config.getPasswordHash());
			return userOk && passwordOk;
		}).subscribeOn(Schedulers.boundedElastic()).flatMap(ok -> {
			if (!ok) {
				return chain.filter(exchange);
			}
			RestAuthenticationToken token = new RestAuthenticationToken(
					new AuthenticatedPrincipal(user, List.of(), AuthMethod.BASIC));
			return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(token));
		});
	}

	private boolean sourceAllowed(ServerWebExchange exchange) {
		InetSocketAddress remote = exchange.getRequest().getRemoteAddress();
		if (remote == null || remote.getAddress() == null) {
			return false;
		}
		String ip = remote.getAddress().getHostAddress();
		for (String cidr : config.getAllowedCidrs()) {
			if (Cidrs.contains(cidr, ip)) {
				return true;
			}
		}
		return false;
	}

	private static String[] decode(String base64) {
		try {
			String decoded = new String(Base64.getDecoder().decode(base64.trim()), StandardCharsets.UTF_8);
			int colon = decoded.indexOf(':');
			if (colon < 0) {
				return null;
			}
			return new String[]{decoded.substring(0, colon), decoded.substring(colon + 1)};
		} catch (IllegalArgumentException badBase64) {
			return null;
		}
	}
}
