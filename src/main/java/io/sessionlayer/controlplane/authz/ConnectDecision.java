package io.sessionlayer.controlplane.authz;

import java.util.UUID;

/**
 * The orchestrated connect-time outcome the {@code Authorize} RPC returns. On
 * {@link #allowed} {@link #signedContext}, {@link #sessionToken},
 * {@link #recordingToken} and {@link #nodeConnection} are present; on a deny
 * (including a Lock, and any fail-closed error) they are null — no token is
 * minted (a denied session is never recorded because it never runs), no
 * connection material is disclosed (§8.4).
 *
 * <p>
 * {@link #trace} carries the non-content correlation the {@code cp.authorize}
 * span + the establishment SLO metric stamp (access model, node id, and the
 * {@code correlation_id} pivot to the audit/recording chain — never any content).
 * It is present on allow and null on deny.
 */
public record ConnectDecision(boolean allowed, SignedDecisionContext signedContext, String sessionToken,
		String recordingToken, NodeConnectionInfo nodeConnection, TraceInfo trace) {

	/** Safe span/metric correlation for an allow (IDs + the access-model enum only). */
	public record TraceInfo(String accessModel, UUID nodeId, UUID correlationId) {
	}

	public static ConnectDecision allow(SignedDecisionContext signedContext, String sessionToken, String recordingToken,
			NodeConnectionInfo nodeConnection, TraceInfo trace) {
		return new ConnectDecision(true, signedContext, sessionToken, recordingToken, nodeConnection, trace);
	}

	public static ConnectDecision denied() {
		return new ConnectDecision(false, null, null, null, null, null);
	}
}
