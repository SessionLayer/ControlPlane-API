package io.sessionlayer.controlplane.grpc;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.authz.ConnectAuthorizationService;
import io.sessionlayer.controlplane.authz.ConnectDecision;
import io.sessionlayer.controlplane.authz.NodeConnectionInfo;
import io.sessionlayer.controlplane.authz.SignedDecisionContext;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.ConnectorKind;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.HostVerification;
import io.sessionlayer.controlplane.grpc.v1.NodeConnection;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import io.sessionlayer.controlplane.observability.CpTracing;
import io.sessionlayer.controlplane.observability.SloMetrics;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * gRPC server for the connect-time decision (Part B, FR-CHAN-1). mTLS-required
 * tier: the {@link AuthInterceptor} authenticates the calling Gateway, and the
 * minted token is bound to <b>that</b> caller (never a request field). The
 * handler delegates to {@link ConnectAuthorizationService} and maps the outcome
 * onto the wire: on allow, the signed decision context + minted token; on deny,
 * one generic {@code DECISION_DENY} with nothing else populated (§7.1).
 */
@Service
public class AuthorizationService extends AuthorizationGrpc.AuthorizationImplBase {

	private final ConnectAuthorizationService authorization;
	private final MtlsProperties properties;
	private final CpTracing tracing;
	private final SloMetrics metrics;

	public AuthorizationService(ConnectAuthorizationService authorization, MtlsProperties properties, CpTracing tracing,
			SloMetrics metrics) {
		this.authorization = authorization;
		this.properties = properties;
		this.tracing = tracing;
		this.metrics = metrics;
	}

	@Override
	public void authorize(AuthorizeRequest request, StreamObserver<AuthorizeResponse> observer) {
		MtlsPeer peer = MtlsContext.peer();
		// Read the extracted trace parent synchronously on the gRPC thread (it lives in
		// the gRPC Context, not the reactive chain that runs off it).
		io.opentelemetry.context.Context traceParent = CpTracing.OTEL_PARENT.get();
		// The mTLS-required tier guarantees a resolved peer, but never NPE if it isn't:
		// a null caller fails closed to a generic deny in the service (missing input).
		UUID caller = peer == null ? null : peer.gatewayId();
		// The break-glass token (field 8) is carried through: when present the CP
		// consumes
		// it atomically, raises the activation + alert, and evaluates the break-glass
		// allow
		// subject to the Lock. The AUTHENTICATED caller is the mTLS peer, never a
		// field.
		// node_name (field 9) is server-side authoritative when set: the CP resolves it
		// via findByName and ignores node_id (§2.6/§11; closes
		// F-ha-connect-nodename-1).
		Mono<ConnectDecision> decision = authorization.authorize(caller, request.getIdentity(),
				request.getIdentityGroupsList(), parseUuid(request.getNodeId()), blankToNull(request.getNodeName()),
				blankToNull(request.getRequestedPrincipal()), blankToNull(request.getSourceIp()),
				parseUuid(request.getSessionId()), blankToNull(request.getBreakglassToken()));
		// Establishment SLO (NFR-4) times the CP machine work; the span (§14) makes it a
		// child of the Gateway root. Both carry correlation only — never content.
		Mono<AuthorizeResponse> result = tracing
				.traceAuthorize(traceParent, blankToNull(request.getSessionId()), blankToNull(request.getNodeId()),
						metrics.timeEstablishment(decision))
				.map(AuthorizationService::toResponse);
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "Authorize");
	}

	private static AuthorizeResponse toResponse(ConnectDecision decision) {
		if (!decision.allowed()) {
			return AuthorizeResponse.newBuilder().setDecision(Decision.DECISION_DENY).build();
		}
		SignedDecisionContext signed = decision.signedContext();
		AuthorizeResponse.Builder builder = AuthorizeResponse.newBuilder().setDecision(Decision.DECISION_ALLOW)
				.setContext(signed.context()).setSignedContext(ByteString.copyFrom(signed.signedContext()))
				.setSignature(ByteString.copyFrom(signed.signature()))
				.setSignerCertificate(ByteString.copyFrom(signed.signerCertificateDer()))
				.setSessionToken(decision.sessionToken()).setRecordingToken(decision.recordingToken());
		signed.caChainDer().forEach(der -> builder.addSignerCaChain(ByteString.copyFrom(der)));
		if (decision.nodeConnection() != null) {
			builder.setNodeConnection(toNodeConnection(decision.nodeConnection()));
		}
		return builder.build();
	}

	private static NodeConnection toNodeConnection(NodeConnectionInfo info) {
		HostVerification.Builder verification = HostVerification.newBuilder();
		info.hostCaKeys().forEach(key -> verification.addHostCaKeys(ByteString.copyFrom(key)));
		info.expectedPrincipals().forEach(verification::addExpectedHostPrincipals);
		info.pinnedHostKeys().forEach(key -> verification.addPinnedHostKeys(ByteString.copyFrom(key)));
		info.hostCertificates().forEach(cert -> verification.addHostCertificates(ByteString.copyFrom(cert)));
		NodeConnection.Builder builder = NodeConnection.newBuilder()
				.setConnectorKind(connectorKind(info.connectorKind())).setNodeName(info.nodeName())
				.setDialAddress(info.dialAddress()).setHostVerification(verification.build());
		// HA owner fields ride only when a fresh presence owner exists (agent nodes);
		// empty otherwise so the ingress Gateway fails closed to "node offline"
		// (§10.2).
		if (info.hasOwner()) {
			builder.setOwningGatewayId(info.owningGatewayId()).setOwningGatewayAddr(info.owningGatewayAddr())
					.setOwnerNonce(info.ownerNonce()).setOwnerNonceId(info.ownerNonceId());
		}
		return builder.build();
	}

	private static ConnectorKind connectorKind(NodeConnectionInfo.ConnectorModel model) {
		return switch (model) {
			case AGENTLESS -> ConnectorKind.CONNECTOR_KIND_AGENTLESS;
			case OUTBOUND_AGENT -> ConnectorKind.CONNECTOR_KIND_OUTBOUND_AGENT;
			case UNSPECIFIED -> ConnectorKind.CONNECTOR_KIND_UNSPECIFIED;
		};
	}

	private static UUID parseUuid(String value) {
		if (value == null || value.isBlank()) {
			return null;
		}
		try {
			return UUID.fromString(value);
		} catch (IllegalArgumentException notAUuid) {
			return null; // a malformed id denies (missing/invalid input, fail closed)
		}
	}

	private static String blankToNull(String value) {
		return value == null || value.isBlank() ? null : value;
	}
}
