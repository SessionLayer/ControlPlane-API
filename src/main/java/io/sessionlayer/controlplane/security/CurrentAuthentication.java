package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.platform.PlatformSubject;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Resolves the authenticated caller from the reactive security context for a
 * controller — bridging whichever REST scheme authenticated (bearer / machine /
 * mTLS) to the platform-RBAC {@link PlatformSubject}. Empty when
 * unauthenticated (the security chain would already have denied a protected
 * exchange).
 */
@Component
public class CurrentAuthentication {

	public Mono<AuthenticatedPrincipal> principal() {
		return ReactiveSecurityContextHolder.getContext().map(ctx -> ctx.getAuthentication())
				.filter(a -> a != null && a.isAuthenticated() && a.getPrincipal() instanceof AuthenticatedPrincipal)
				.map(a -> (AuthenticatedPrincipal) a.getPrincipal());
	}

	public Mono<PlatformSubject> subject() {
		return principal().map(AuthenticatedPrincipal::toPlatformSubject);
	}
}
