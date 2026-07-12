package io.sessionlayer.controlplane.web;

/**
 * A lock create request that failed ingest validation (D5) — an
 * empty/unrecognised target, a blank facet value, a malformed node label, or a
 * non-positive TTL. Surfaced as an RFC-9457 {@code 400} by
 * {@link LockExceptionHandler}. The message is operator-facing and safe to
 * return (it describes the request shape, never any secret).
 */
public class LockValidationException extends RuntimeException {

	public LockValidationException(String message) {
		super(message);
	}
}
