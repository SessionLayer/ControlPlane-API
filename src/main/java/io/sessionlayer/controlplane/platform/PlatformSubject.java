package io.sessionlayer.controlplane.platform;

import java.util.List;

/**
 * The admin actor a platform-RBAC decision is made for: a resolved identity and
 * its SSO/OIDC groups. A {@code role_binding} targets either the identity
 * ({@code subject_kind=user}) or one of the groups
 * ({@code subject_kind=group}).
 */
public record PlatformSubject(String identity, List<String> groups) {

	public PlatformSubject {
		groups = (groups == null) ? List.of() : List.copyOf(groups);
	}
}
