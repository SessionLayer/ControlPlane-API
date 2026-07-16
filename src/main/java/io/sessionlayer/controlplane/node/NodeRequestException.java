package io.sessionlayer.controlplane.node;

/**
 * A fail-closed rejection from {@link NodeLifecycleService}. Carries a
 * {@link Reason} the REST layer maps to an RFC-9457 status
 * ({@code 400}/{@code 404}/{@code 409}). The message is operator-facing (an
 * admin API); it never reaches the SSH user.
 */
public class NodeRequestException extends RuntimeException {

	/**
	 * The rejection category, mapped to an HTTP status by the controller advice.
	 */
	public enum Reason {
		/** Malformed input (bad name/address, missing host anchor) — 400. */
		INVALID_ARGUMENT,
		/** The node id does not exist — 404. */
		NOT_FOUND,
		/** A node with that name is already registered — 409. */
		CONFLICT
	}

	private final Reason reason;

	public NodeRequestException(Reason reason, String message) {
		super(message);
		this.reason = reason;
	}

	public Reason reason() {
		return reason;
	}
}
