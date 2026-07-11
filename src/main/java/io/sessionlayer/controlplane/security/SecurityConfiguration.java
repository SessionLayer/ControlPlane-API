package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.machine.MachineTokenProperties;
import io.sessionlayer.controlplane.machine.MachineTokenSigner;
import io.sessionlayer.controlplane.oidc.IdTokenValidator;
import io.sessionlayer.controlplane.oidc.IdpJwtDecoder;
import io.sessionlayer.controlplane.oidc.OidcProperties;
import io.sessionlayer.controlplane.oidc.ResolvedIdentity;
import io.sessionlayer.controlplane.security.mtls.MtlsAuthenticationConverter;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The REST security spine (FR-AUTH-17, Design §5.7). A single reactive filter
 * chain wiring the three first-class schemes:
 * <ul>
 * <li><b>OIDC bearer JWT</b> + <b>OAuth client-credentials machine tokens</b>
 * via {@code oauth2ResourceServer} with a per-issuer manager resolver (external
 * IdP vs the CP's own machine-token issuer). ID tokens are validated with a
 * positive alg allow-list (Part B); machine tokens are CP-signed (Part F).</li>
 * <li><b>mTLS</b> via a client-certificate filter re-validated against the
 * internal CA trust anchor.</li>
 * </ul>
 * Public, non-leaking endpoints (meta probes, the browser OIDC pages, the token
 * endpoint that authenticates its own client, and back-channel logout) are
 * {@code permitAll}; everything else is {@code authenticated} and fails closed
 * (NFR-2). HTTP Basic is disabled unless the escape hatch is explicitly enabled
 * (behind an IP allow-list + a startup warning). Per-endpoint platform-RBAC is
 * enforced in the controllers via {@code PlatformAuthorization}.
 */
@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
@EnableConfigurationProperties({SecurityProperties.class, OidcProperties.class, MachineTokenProperties.class})
public class SecurityConfiguration {

	private static final Logger LOG = LoggerFactory.getLogger(SecurityConfiguration.class);

	static final String[] PUBLIC_PATHS = {"/v1/healthz", "/v1/version", "/actuator/health", "/actuator/health/**",
			"/actuator/info", "/v1/auth/verify", "/v1/auth/callback", "/v1/auth/device/**"};

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	SecurityWebFilterChain restSecurityFilterChain(ServerHttpSecurity http, MtlsAuthenticationConverter mtlsConverter,
			ReactiveAuthenticationManagerResolver<ServerWebExchange> jwtManagerResolver, SecurityProperties security,
			PasswordEncoder passwordEncoder) {
		http.csrf(ServerHttpSecurity.CsrfSpec::disable).formLogin(ServerHttpSecurity.FormLoginSpec::disable)
				.logout(ServerHttpSecurity.LogoutSpec::disable).httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
				.authorizeExchange(ex -> ex.pathMatchers(PUBLIC_PATHS).permitAll()
						.pathMatchers(HttpMethod.POST, "/v1/oauth2/token", "/v1/auth/backchannel-logout").permitAll()
						.anyExchange().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(jwtManagerResolver))
				.addFilterAt(mtlsAuthenticationFilter(mtlsConverter), SecurityWebFiltersOrder.AUTHENTICATION);

		SecurityProperties.BasicAuth basic = security.getBasicAuth();
		if (basic.isEnabled()) {
			LOG.warn(
					"HTTP Basic escape hatch ENABLED (FR-AUTH-17): a discouraged, non-first-class scheme. "
							+ "It is gated to CIDRs {} and MUST sit behind mTLS. Disable it in normal operation.",
					basic.getAllowedCidrs());
			http.addFilterAt(new BasicEscapeHatchFilter(basic, passwordEncoder), SecurityWebFiltersOrder.HTTP_BASIC);
		}
		return http.build();
	}

	/** mTLS runs as an authentication filter: a valid client cert → identity. */
	private AuthenticationWebFilter mtlsAuthenticationFilter(MtlsAuthenticationConverter converter) {
		// The converter returns an already-authenticated token; the manager just echoes
		// it.
		AuthenticationWebFilter filter = new AuthenticationWebFilter((ReactiveAuthenticationManager) Mono::just);
		filter.setServerAuthenticationConverter(converter);
		return filter;
	}

	/**
	 * Bearer resolver keyed by token issuer: the external IdP (human ID tokens,
	 * Part B) and the CP's own machine-token issuer (Part F). An unknown issuer
	 * resolves to no manager → the bearer token is rejected (fail closed).
	 */
	@Bean
	ReactiveAuthenticationManagerResolver<ServerWebExchange> jwtManagerResolver(IdpJwtDecoder idpDecoder,
			IdTokenValidator idTokenValidator, OidcProperties oidc, MachineTokenSigner machineTokenSigner,
			MachineTokenProperties machine) {
		ReactiveAuthenticationManager idpManager = idpManager(idpDecoder, idTokenValidator);
		ReactiveAuthenticationManager cpManager = cpMachineTokenManager(machineTokenSigner, machine);
		ReactiveAuthenticationManagerResolver<String> byIssuer = issuer -> {
			if (oidc.isEnabled() && issuer.equals(oidc.getIssuer())) {
				return Mono.just(idpManager);
			}
			if (issuer.equals(machine.getIssuer())) {
				return Mono.just(cpManager);
			}
			return Mono.empty();
		};
		return new JwtIssuerReactiveAuthenticationManagerResolver(byIssuer);
	}

	private ReactiveAuthenticationManager idpManager(IdpJwtDecoder idpDecoder, IdTokenValidator idTokenValidator) {
		JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(idpDecoder);
		manager.setJwtAuthenticationConverter(jwt -> {
			ResolvedIdentity resolved = idTokenValidator.resolve(jwt);
			return Mono.just(new RestAuthenticationToken(
					new AuthenticatedPrincipal(resolved.identity(), resolved.groups(), AuthMethod.OIDC_BEARER)));
		});
		return manager;
	}

	private ReactiveAuthenticationManager cpMachineTokenManager(MachineTokenSigner signer,
			MachineTokenProperties machine) {
		NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withPublicKey(signer.publicKey()).build();
		decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
				new org.springframework.security.oauth2.jwt.JwtTimestampValidator(machine.getClockSkew()),
				new org.springframework.security.oauth2.jwt.JwtIssuerValidator(machine.getIssuer())));
		JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(decoder);
		manager.setJwtAuthenticationConverter(jwt -> {
			List<String> groups = jwt.getClaimAsStringList("groups");
			return Mono.just(new RestAuthenticationToken(new AuthenticatedPrincipal(jwt.getSubject(),
					groups == null ? List.of() : groups, AuthMethod.CLIENT_CREDENTIALS)));
		});
		return manager;
	}

	ReactiveJwtDecoder machineTokenDecoder(MachineTokenSigner signer) {
		return NimbusReactiveJwtDecoder.withPublicKey(signer.publicKey()).build();
	}
}
