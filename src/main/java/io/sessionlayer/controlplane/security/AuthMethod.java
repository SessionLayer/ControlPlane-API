package io.sessionlayer.controlplane.security;

/** The first-class REST authentication schemes (FR-AUTH-17, Design §5.7). */
public enum AuthMethod {
	/** OIDC bearer ID token validated by the CP (the authentication proof). */
	OIDC_BEARER,
	/** A CP-issued OAuth client-credentials machine token (FR-AUTH-12). */
	CLIENT_CREDENTIALS,
	/** Mutual TLS: a client certificate chained to the internal CA. */
	MTLS,
	/**
	 * HTTP Basic — NOT first-class; off unless explicitly enabled (escape hatch).
	 */
	BASIC
}
