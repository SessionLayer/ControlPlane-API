package io.sessionlayer.controlplane.grpc;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.agent.AgentEnrollmentService;
import io.sessionlayer.controlplane.agent.AgentRenewalService;
import io.sessionlayer.controlplane.agent.IssuedAgentIdentity;
import io.sessionlayer.controlplane.grpc.v1.AgentIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.EnrollAgentRequest;
import io.sessionlayer.controlplane.grpc.v1.EnrollAgentResponse;
import io.sessionlayer.controlplane.grpc.v1.RenewAgentIdentityRequest;
import io.sessionlayer.controlplane.grpc.v1.RenewAgentIdentityResponse;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import org.springframework.stereotype.Service;

/**
 * gRPC server for {@code AgentIdentity} (S12): {@code EnrollAgent}
 * (bootstrap-tier, JoinMethod-proof-authenticated) and
 * {@code RenewAgentIdentity} (mTLS-required; the caller agent is resolved by
 * the {@link AuthInterceptor} into the gRPC context). Mirrors
 * {@link GatewayIdentityService} — both bridge the reactive services to the
 * callback API without blocking. Registered as a
 * {@link io.grpc.BindableService} and bound onto the mTLS gRPC server behind
 * the interceptor.
 */
@Service
public class AgentIdentityService extends AgentIdentityGrpc.AgentIdentityImplBase {

	private final AgentEnrollmentService enrollment;
	private final AgentRenewalService renewal;
	private final MtlsProperties properties;

	public AgentIdentityService(AgentEnrollmentService enrollment, AgentRenewalService renewal,
			MtlsProperties properties) {
		this.enrollment = enrollment;
		this.renewal = renewal;
		this.properties = properties;
	}

	@Override
	public void enrollAgent(EnrollAgentRequest request, StreamObserver<EnrollAgentResponse> observer) {
		ReactiveBridge.forward(enrollment.enroll(request).map(AgentIdentityService::toEnrollResponse), observer,
				properties.getRpcTimeout(), "EnrollAgent");
	}

	@Override
	public void renewAgentIdentity(RenewAgentIdentityRequest request,
			StreamObserver<RenewAgentIdentityResponse> observer) {
		// The interceptor resolved the caller synchronously into the gRPC context; read
		// it before subscribing (the reactive callbacks run on other threads). Resolve
		// the caller agent ONLY from the re-validated client-cert SAN, never a field.
		MtlsPeer peer = MtlsContext.peer();
		String presentedFingerprint = peer.certificate() == null
				? null
				: CertificateFingerprints.sha256Hex(peer.certificate());
		ReactiveBridge.forward(
				renewal.renew(peer.agentId(), presentedFingerprint, request.getPkcs10Csr().toByteArray(),
						request.getCurrentGeneration()).map(AgentIdentityService::toRenewResponse),
				observer, properties.getRpcTimeout(), "RenewAgentIdentity");
	}

	private static EnrollAgentResponse toEnrollResponse(IssuedAgentIdentity issued) {
		return EnrollAgentResponse.newBuilder().setCertificate(ByteString.copyFrom(issued.certificate()))
				.addAllCaChain(caChain(issued)).setAgentId(issued.agentId().toString())
				.setNodeId(issued.nodeId().toString()).setGeneration(issued.generation())
				.setNotBeforeEpochSeconds(issued.notBeforeEpochSeconds())
				.setNotAfterEpochSeconds(issued.notAfterEpochSeconds()).build();
	}

	private static RenewAgentIdentityResponse toRenewResponse(IssuedAgentIdentity issued) {
		return RenewAgentIdentityResponse.newBuilder().setCertificate(ByteString.copyFrom(issued.certificate()))
				.addAllCaChain(caChain(issued)).setAgentId(issued.agentId().toString())
				.setNodeId(issued.nodeId().toString()).setGeneration(issued.generation())
				.setNotBeforeEpochSeconds(issued.notBeforeEpochSeconds())
				.setNotAfterEpochSeconds(issued.notAfterEpochSeconds()).build();
	}

	private static Iterable<ByteString> caChain(IssuedAgentIdentity issued) {
		return issued.caChain().stream().map(ByteString::copyFrom).toList();
	}
}
