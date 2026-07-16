package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * The shared platform-RBAC gate for the management controllers (FR-API-5,
 * FR-PADM-3): resolve the authenticated subject, authorize the (unscoped)
 * permission, and run {@code action} only on allow — otherwise a generic
 * {@code 403} with no body (no existence/permission disclosure). Extracted so
 * every Session 17 CRUD controller reuses one deny-by-default idiom instead of
 * re-implementing it (the pattern the S16 controllers each inlined).
 */
@Component
public class PlatformAccess {

	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;

	public PlatformAccess(PlatformAuthorization platformAuthorization, CurrentAuthentication currentAuthentication) {
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
	}

	public <T> Mono<ResponseEntity<T>> withPermission(String permission,
			Function<PlatformSubject, Mono<ResponseEntity<T>>> action) {
		return currentAuthentication.subject()
				.flatMap(subject -> platformAuthorization.authorize(subject, permission, null)
						.flatMap(decision -> decision.allowed()
								? action.apply(subject)
								: Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<T>build())))
				.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}
}
