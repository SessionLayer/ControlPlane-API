package io.sessionlayer.controlplane.web;

/**
 * A join-token issue request that failed ingest validation (an invalid
 * {@code nodeName}). Surfaced as an RFC-9457 {@code 400} by
 * {@link JoinTokenExceptionHandler}. The message is operator-facing and safe to
 * return (it describes the request shape, never any secret).
 */
public class JoinTokenValidationException extends RuntimeException {

	public JoinTokenValidationException(String message) {
		super(message);
	}
}
