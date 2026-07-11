package io.sessionlayer.controlplane.authz;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The resolved, connect-time decision input for the data-plane evaluator — a
 * pure value (no I/O). Identity resolution (OIDC/OTP/pins) is upstream (S6);
 * the node's labels are resolved from inventory before the evaluator runs. The
 * decision is a pure function of {@code (this, grant-set, lock-set)}.
 *
 * @param identity
 *            the resolved subject identity (never the source IP)
 * @param groups
 *            the subject's SSO/OIDC groups (may be empty)
 * @param nodeId
 *            the fixed target node
 * @param nodeLabels
 *            the node's resolved labels (key -&gt; value)
 * @param sourceIp
 *            the client source address (deny-only reducer, FR-AUTH-15) — may be
 *            null/unknown, in which case any source-restricted grant fails
 *            closed
 * @param requestedPrincipal
 *            the Linux login the user is requesting (may be null for a "what
 *            may I do" query); becomes the cert principal on allow
 */
public record AuthorizationRequest(String identity, List<String> groups, UUID nodeId, Map<String, String> nodeLabels,
		String sourceIp, String requestedPrincipal) {

	public AuthorizationRequest {
		groups = (groups == null) ? List.of() : List.copyOf(groups);
		nodeLabels = (nodeLabels == null) ? Map.of() : Map.copyOf(nodeLabels);
	}
}
