package io.sessionlayer.controlplane.mtls;

import java.security.cert.X509Certificate;
import java.util.UUID;

/**
 * The authenticated peer resolved by the {@code AuthInterceptor} for one RPC:
 * the caller's leaf certificate and the principal id parsed from its SAN URI.
 * The mTLS plane carries two principal namespaces — Gateways
 * ({@code sessionlayer://gateway/<id>}) and Agents
 * ({@code sessionlayer://agent/<id>}, S12) — and a leaf resolves to exactly one
 * (they never overlap). {@link #NONE} represents a call with no valid client
 * certificate (the bootstrap tier). At most one of {@code gatewayId}/
 * {@code agentId} is non-null.
 */
public record MtlsPeer(UUID gatewayId, UUID agentId, X509Certificate certificate) {

	/** No valid client certificate (bootstrap-tier caller). */
	public static final MtlsPeer NONE = new MtlsPeer(null, null, null);

	/** A resolved Gateway caller. */
	public static MtlsPeer gateway(UUID gatewayId, X509Certificate certificate) {
		return new MtlsPeer(gatewayId, null, certificate);
	}

	/** A resolved Agent caller (S12). */
	public static MtlsPeer agent(UUID agentId, X509Certificate certificate) {
		return new MtlsPeer(null, agentId, certificate);
	}

	/**
	 * True when a valid client certificate resolved to a gateway or agent identity.
	 */
	public boolean authenticated() {
		return gatewayId != null || agentId != null;
	}
}
