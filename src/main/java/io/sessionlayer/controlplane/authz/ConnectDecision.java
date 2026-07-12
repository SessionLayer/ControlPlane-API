package io.sessionlayer.controlplane.authz;

/**
 * The orchestrated connect-time outcome the {@code Authorize} RPC returns. On
 * {@link #allowed} {@link #signedContext}, {@link #sessionToken},
 * {@link #recordingToken} and {@link #nodeConnection} are present; on a deny
 * (including a Lock, and any fail-closed error) they are null — no token is
 * minted (a denied session is never recorded because it never runs), no
 * connection material is disclosed (§8.4).
 */
public record ConnectDecision(boolean allowed, SignedDecisionContext signedContext, String sessionToken,
		String recordingToken, NodeConnectionInfo nodeConnection) {

	public static ConnectDecision allow(SignedDecisionContext signedContext, String sessionToken, String recordingToken,
			NodeConnectionInfo nodeConnection) {
		return new ConnectDecision(true, signedContext, sessionToken, recordingToken, nodeConnection);
	}

	public static ConnectDecision denied() {
		return new ConnectDecision(false, null, null, null, null);
	}
}
