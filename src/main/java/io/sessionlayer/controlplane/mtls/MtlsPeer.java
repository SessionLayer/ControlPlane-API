package io.sessionlayer.controlplane.mtls;

import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * The authenticated peer resolved by the {@code AuthInterceptor} for one RPC:
 * the caller's leaf certificate and the {@code gateway_identity} id parsed from
 * its SAN URI. {@link #NONE} represents a call with no valid client certificate
 * (the bootstrap tier). {@code gatewayId} is null unless a valid client
 * certificate chained to the internal CA was presented and carried a gateway
 * identity URI.
 */
public record MtlsPeer(UUID gatewayId, X509Certificate certificate) {

	/** No valid client certificate (bootstrap-tier caller). */
	public static final MtlsPeer NONE = new MtlsPeer(null, null);

	/** True when a valid client certificate resolved to a gateway identity. */
	public boolean authenticated() {
		return gatewayId != null;
	}
}
