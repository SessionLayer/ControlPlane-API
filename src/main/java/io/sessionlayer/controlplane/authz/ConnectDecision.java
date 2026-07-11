package io.sessionlayer.controlplane.authz;

/**
 * The orchestrated connect-time outcome the {@code Authorize} RPC returns. On
 * {@link #allowed} {@link #signedContext}, {@link #sessionToken} and
 * {@link #nodeConnection} are present; on a deny (including a Lock, and any
 * fail-closed error) they are null — no token is minted, no connection material
 * is disclosed (§8.4).
 */
public record ConnectDecision(boolean allowed, SignedDecisionContext signedContext, String sessionToken,
		NodeConnectionInfo nodeConnection) {

	public static ConnectDecision allow(SignedDecisionContext signedContext, String sessionToken,
			NodeConnectionInfo nodeConnection) {
		return new ConnectDecision(true, signedContext, sessionToken, nodeConnection);
	}

	public static ConnectDecision denied() {
		return new ConnectDecision(false, null, null, null);
	}
}
