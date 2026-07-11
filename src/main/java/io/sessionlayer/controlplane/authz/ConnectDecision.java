package io.sessionlayer.controlplane.authz;

/**
 * The orchestrated connect-time outcome the {@code Authorize} RPC returns. On
 * {@link #allowed} both {@link #signedContext} and {@link #sessionToken} are
 * present; on a deny (including a Lock, and any fail-closed error) they are
 * null — no token is minted (§8.4).
 */
public record ConnectDecision(boolean allowed, SignedDecisionContext signedContext, String sessionToken) {

	public static ConnectDecision allow(SignedDecisionContext signedContext, String sessionToken) {
		return new ConnectDecision(true, signedContext, sessionToken);
	}

	public static ConnectDecision denied() {
		return new ConnectDecision(false, null, null);
	}
}
