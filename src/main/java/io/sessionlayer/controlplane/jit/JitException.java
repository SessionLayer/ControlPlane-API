package io.sessionlayer.controlplane.jit;

/**
 * A JIT state-machine error, mapped by the controller's handler to an RFC-9457
 * problem with the right status. The message is operator-facing (JIT is a
 * platform-RBAC surface, not an anonymous auth path), but never leaks a secret.
 */
public class JitException extends RuntimeException {

	public enum Reason {
		NOT_FOUND, INVALID, NOT_REQUESTABLE, NOT_PENDING, SELF_APPROVAL, NOT_AN_APPROVER, ALREADY_ACTED, NOT_REVOCABLE
	}

	private final transient Reason reason;

	public JitException(Reason reason, String message) {
		super(message);
		this.reason = reason;
	}

	public Reason reason() {
		return reason;
	}
}
