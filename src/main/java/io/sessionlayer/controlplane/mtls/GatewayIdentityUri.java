package io.sessionlayer.controlplane.mtls;

import java.util.Optional;
import java.util.UUID;

/**
 * The URI SubjectAlternativeName that binds a Gateway's mTLS client certificate
 * to its {@code gateway_identity} row: {@code sessionlayer://gateway/<id>}. The
 * enrollment/renewal services stamp it into the issued cert; the
 * {@code AuthInterceptor} parses it from a presented client cert to resolve the
 * caller's {@code gateway_identity} (the SAN → identity mapping in
 * VERSIONING.md §7). A missing/malformed URI resolves to empty and is refused
 * on the mTLS-required tiers (fail closed).
 */
public final class GatewayIdentityUri {

	private static final String PREFIX = "sessionlayer://gateway/";

	private GatewayIdentityUri() {
	}

	/** The identity URI for a gateway id. */
	public static String of(UUID gatewayId) {
		return PREFIX + gatewayId;
	}

	/** Parse a gateway id from an identity URI, or empty if not one. */
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
