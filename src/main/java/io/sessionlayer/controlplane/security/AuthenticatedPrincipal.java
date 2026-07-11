package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.platform.PlatformSubject;
import java.util.List;

/**
 * The resolved, authenticated caller of a REST request: an {@code identity} and
 * its {@code groups}, plus which first-class scheme proved it (FR-AUTH-17).
 * This is the Authentication principal for every authenticated request,
 * whichever scheme authenticated it, so a controller bridges uniformly to
 * platform-RBAC.
 */
public record AuthenticatedPrincipal(String identity, List<String> groups, AuthMethod method) {

	public AuthenticatedPrincipal {
		groups = (groups == null) ? List.of() : List.copyOf(groups);
	}

	public PlatformSubject toPlatformSubject() {
		return new PlatformSubject(identity, groups);
	}
}
