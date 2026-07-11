package io.sessionlayer.controlplane.gateway;

import java.util.UUID;

/**
 * The advisory, NON-authoritative context a {@code SignSessionCertificate}
 * request may carry (the proto {@code SignContext}). The session token is the
 * sole authority for {@code {session, node, principal}}; if a context field is
 * present here it MUST agree with the token, else the request fails closed
 * (§15). Any field may be {@code null} (unset).
 */
public record SignRequestContext(UUID sessionId, UUID nodeId, String principal) {

	/** The empty context (nothing asserted). */
	public static final SignRequestContext EMPTY = new SignRequestContext(null, null, null);
}
