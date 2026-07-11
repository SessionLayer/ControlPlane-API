package io.sessionlayer.controlplane.mtls;

import io.grpc.Context;

/**
 * Carries the {@link MtlsPeer} resolved by the {@code AuthInterceptor} into the
 * gRPC {@link Context} so handlers read the authenticated caller without
 * re-parsing the TLS session.
 */
public final class MtlsContext {

	/** The per-call authenticated peer (never null once the interceptor ran). */
	public static final Context.Key<MtlsPeer> PEER = Context.key("sessionlayer.mtls.peer");

	private MtlsContext() {
	}

	/** The current call's peer, or {@link MtlsPeer#NONE} if unset. */
	public static MtlsPeer peer() {
		MtlsPeer peer = PEER.get();
		return peer == null ? MtlsPeer.NONE : peer;
	}
}
