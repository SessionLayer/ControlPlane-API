package io.sessionlayer.controlplane.mtls;

import java.util.Optional;
import java.util.UUID;

/**
 * The URI SubjectAlternativeName that binds an Agent's mTLS client certificate
 * to its {@code agent_identity} row: {@code sessionlayer://agent/<id>}. The
 * enrollment/renewal services stamp it into the issued cert; the
 * {@code AuthInterceptor} parses it from a presented client cert to resolve the
 * caller's {@code agent_identity} for the mTLS-required tier
 * ({@code RenewAgentIdentity}). Mirrors {@link GatewayIdentityUri}; the
 * distinct {@code agent} authority keeps the two principal namespaces separate
 * so a gateway cert never resolves to an agent and vice versa. A
 * missing/malformed URI resolves to empty and is refused on the mTLS-required
 * tier (fail closed).
 */
public final class AgentIdentityUri {

	private static final String PREFIX = "sessionlayer://agent/";

	private AgentIdentityUri() {
	}

	/** The identity URI for an agent id. */
	public static String of(UUID agentId) {
		return PREFIX + agentId;
	}

	/** Parse an agent id from an identity URI, or empty if not one. */
	public static Optional<UUID> parse(String uri) {
		if (uri == null || !uri.startsWith(PREFIX)) {
			return Optional.empty();
		}
		try {
			return Optional.of(UUID.fromString(uri.substring(PREFIX.length())));
		} catch (IllegalArgumentException notAUuid) {
			return Optional.empty();
		}
	}
}
