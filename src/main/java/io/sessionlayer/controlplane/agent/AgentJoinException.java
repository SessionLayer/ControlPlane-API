package io.sessionlayer.controlplane.agent;

/**
 * A fail-closed rejection of an Agent join/renew RPC. Carries a {@link Reason}
 * the gRPC handlers map to a status code and a <b>generic, non-leaking</b>
 * public message (the specific cause is logged/audited, never returned — §15 /
 * NFR-2). Every JoinMethod-verification and identity-path failure surfaces as
 * one of these so a caller cannot distinguish (say) "wrong node" from "expired
 * token" from "already enrolled". The exact mirror of
 * {@code GatewayRequestException}; kept a distinct type so agent code never
 * throws a "gateway" error.
 */
public class AgentJoinException extends RuntimeException {

	/** The fail-closed category, mapped to a gRPC status by the handler. */
	public enum Reason {
		/** No/invalid credential or unauthorized proof — gRPC UNAUTHENTICATED. */
		UNAUTHENTICATED,
		/**
		 * Known but not permitted (locked node, already enrolled) — PERMISSION_DENIED.
		 */
		PERMISSION_DENIED,
		/** Precondition unmet (generation mismatch) — FAILED_PRECONDITION. */
		FAILED_PRECONDITION,
		/** Malformed request (bad CSR/key/proof) — INVALID_ARGUMENT. */
		INVALID_ARGUMENT
	}

	private final Reason reason;

	public AgentJoinException(Reason reason, String publicMessage) {
		super(publicMessage);
		this.reason = reason;
	}

	public Reason reason() {
		return reason;
	}
}
