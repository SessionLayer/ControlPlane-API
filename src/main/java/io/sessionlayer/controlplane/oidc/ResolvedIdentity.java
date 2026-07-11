package io.sessionlayer.controlplane.oidc;

import java.util.List;

/**
 * A server-side-resolved principal (FR-AUTH-8): the authenticated {@code
 * identity} and the {@code groups} mapped from IdP claims. The user never
 * chooses these — they come from validated token claims. {@code groups} feed
 * both the platform-RBAC subject and the data-plane {@code Authorize} request
 * (S5), which maps them to allowed Linux principals.
 */
public record ResolvedIdentity(String identity, List<String> groups, String subject) {
}
