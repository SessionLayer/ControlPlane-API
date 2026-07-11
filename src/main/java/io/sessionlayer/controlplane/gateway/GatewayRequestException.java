package io.sessionlayer.controlplane.gateway;

/**
 * A fail-closed rejection of a Gateway RPC (Parts B/C). Carries a
 * {@link Reason} the gRPC handlers map to a status code and a <b>generic,
 * non-leaking</b> public message (the specific cause is logged/audited, never
 * returned to the caller — §15 / NFR-2). Every authorization/validation failure
 * on the identity and signing paths surfaces as one of these so a caller cannot
 * distinguish "wrong gateway" from "expired token" from "already used".
 */
public class GatewayRequestException extends RuntimeException {

	/** The fail-closed category, mapped to a gRPC status by the handler. */
	public enum Reason {
		/** No/invalid credential — gRPC UNAUTHENTICATED. */
		UNAUTHENTICATED,
		/**
		 * Known but not permitted (locked identity, wrong binding) — PERMISSION_DENIED.
		 */
		PERMISSION_DENIED,
		/** Precondition unmet (generation mismatch) — FAILED_PRECONDITION. */
		FAILED_PRECONDITION,
		/** Malformed request (bad CSR/key) — INVALID_ARGUMENT. */
		INVALID_ARGUMENT
	}

	private final Reason reason;

	public GatewayRequestException(Reason reason, String publicMessage) {
		super(publicMessage);
		this.reason = reason;
	}

	public Reason reason() {
		return reason;
	}
}
