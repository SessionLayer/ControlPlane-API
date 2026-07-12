package io.sessionlayer.controlplane.grpc;

import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Grpc;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.sessionlayer.controlplane.grpc.v1.AgentIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.GatewayIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.HandshakeGrpc;
import io.sessionlayer.controlplane.mtls.AgentIdentityUri;
import io.sessionlayer.controlplane.mtls.GatewayIdentityUri;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The per-RPC authorization interceptor for the mTLS plane (VERSIONING.md §7,
 * Design §15). mTLS authenticates the channel; this interceptor decides, per
 * method, whether a valid client certificate is required and — independently of
 * the TLS-layer {@code clientAuth} toggle — re-validates the presented client
 * chain against the internal CA trust anchor, checks validity, and resolves the
 * caller's {@code gateway_identity} id from the certificate SAN. The resolved
 * {@link MtlsPeer} is placed in the gRPC {@link Context} for handlers.
 *
 * <ul>
 * <li><b>Bootstrap tier</b> ({@code Handshake/Negotiate},
 * {@code GatewayIdentity/EnrollGateway}, {@code AgentIdentity/EnrollAgent}) —
 * reachable without a client cert; the enrollment token / join proof authorises
 * Enroll.</li>
 * <li><b>mTLS-required tier</b> ({@code RenewGatewayIdentity},
 * {@code RenewAgentIdentity}, {@code SignSessionCertificate}, and any unknown
 * method) — refused {@code UNAUTHENTICATED} unless a valid client cert chained
 * to the internal CA resolves to a gateway or agent identity. The
 * active/unlocked check + token binding are enforced reactively by the handlers
 * (fail closed).</li>
 * </ul>
 */
public final class AuthInterceptor implements ServerInterceptor {

	private static final Logger LOG = LoggerFactory.getLogger(AuthInterceptor.class);

	/** GeneralName type for a URI SAN (RFC 5280 §4.2.1.6). */
	private static final int SAN_URI = 6;

	/** Methods reachable without a client certificate (the bootstrap exception). */
	private static final Set<String> BOOTSTRAP_METHODS = Set.of(HandshakeGrpc.getNegotiateMethod().getFullMethodName(),
			GatewayIdentityGrpc.getEnrollGatewayMethod().getFullMethodName(),
			AgentIdentityGrpc.getEnrollAgentMethod().getFullMethodName());

	private final X509TrustManager trustManager;

	public AuthInterceptor(X509TrustManager trustManager) {
		this.trustManager = trustManager;
	}

	@Override
	public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(ServerCall<ReqT, RespT> call, Metadata headers,
			ServerCallHandler<ReqT, RespT> next) {
		MtlsPeer peer = resolvePeer(call);
		boolean bootstrap = BOOTSTRAP_METHODS.contains(call.getMethodDescriptor().getFullMethodName());
		if (!bootstrap && !peer.authenticated()) {
			// mTLS-required tier with no valid, resolvable client certificate → fail
			// closed.
			call.close(Status.UNAUTHENTICATED.withDescription("valid client certificate required"), new Metadata());
			return new ServerCall.Listener<>() {
			};
		}
		Context context = Context.current().withValue(MtlsContext.PEER, peer);
		return Contexts.interceptCall(context, call, headers, next);
	}

	/**
	 * Resolve the caller from the TLS session: independently re-validate the client
	 * chain against the internal CA, check validity, and parse the principal id
	 * from the SAN URI — a gateway URI resolves to a Gateway peer, an agent URI to
	 * an Agent peer (the two namespaces never overlap). Any absence/failure yields
	 * {@link MtlsPeer#NONE} (a bootstrap caller); the tier gate above decides
	 * whether that is acceptable.
	 */
	private MtlsPeer resolvePeer(ServerCall<?, ?> call) {
		SSLSession session = call.getAttributes().get(Grpc.TRANSPORT_ATTR_SSL_SESSION);
		if (session == null) {
			return MtlsPeer.NONE;
		}
		X509Certificate[] chain;
		try {
			chain = toX509(session.getPeerCertificates());
		} catch (SSLPeerUnverifiedException noClientCert) {
			return MtlsPeer.NONE; // client presented no certificate (clientAuth OPTIONAL)
		}
		if (chain.length == 0) {
			return MtlsPeer.NONE;
		}
		try {
			// Independent re-validation against the internal CA trust anchor (not relying
			// solely on the TLS toggle): path build + validity + basic constraints.
			trustManager.checkClientTrusted(chain, chain[0].getPublicKey().getAlgorithm());
		} catch (Exception invalidChain) {
			LOG.debug("client certificate chain rejected on re-validation: {}", invalidChain.toString());
			return MtlsPeer.NONE;
		}
		MtlsPeer peer = principalFromSan(chain[0]);
		if (!peer.authenticated()) {
			LOG.debug("client certificate has no sessionlayer gateway/agent SAN URI");
		}
		return peer;
	}

	private static X509Certificate[] toX509(Certificate[] certificates) {
		X509Certificate[] out = new X509Certificate[certificates.length];
		for (int i = 0; i < certificates.length; i++) {
			out[i] = (X509Certificate) certificates[i];
		}
		return out;
	}

	private static MtlsPeer principalFromSan(X509Certificate leaf) {
		try {
			var sans = leaf.getSubjectAlternativeNames();
			if (sans == null) {
				return MtlsPeer.NONE;
			}
			for (List<?> san : sans) {
				if (san.size() >= 2 && san.get(0) instanceof Integer type && type == SAN_URI
						&& san.get(1) instanceof String uri) {
					UUID gatewayId = GatewayIdentityUri.parse(uri).orElse(null);
					if (gatewayId != null) {
						return MtlsPeer.gateway(gatewayId, leaf);
					}
					UUID agentId = AgentIdentityUri.parse(uri).orElse(null);
					if (agentId != null) {
						return MtlsPeer.agent(agentId, leaf);
					}
				}
			}
			return MtlsPeer.NONE;
		} catch (Exception malformed) {
			return MtlsPeer.NONE;
		}
	}
}
