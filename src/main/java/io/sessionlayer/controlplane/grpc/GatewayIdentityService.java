package io.sessionlayer.controlplane.grpc;

import com.google.protobuf.ByteString;
import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.gateway.GatewayEnrollmentService;
import io.sessionlayer.controlplane.gateway.GatewayRenewalService;
import io.sessionlayer.controlplane.gateway.IssuedIdentity;
import io.sessionlayer.controlplane.grpc.v1.EnrollGatewayRequest;
import io.sessionlayer.controlplane.grpc.v1.EnrollGatewayResponse;
import io.sessionlayer.controlplane.grpc.v1.GatewayIdentityGrpc;
import io.sessionlayer.controlplane.grpc.v1.RenewGatewayIdentityRequest;
import io.sessionlayer.controlplane.grpc.v1.RenewGatewayIdentityResponse;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import org.springframework.stereotype.Service;

/**
 * gRPC server for {@code GatewayIdentity} (Part B): {@code EnrollGateway}
 * (bootstrap-tier, token-authenticated) and {@code RenewGatewayIdentity}
 * (mTLS-required; the caller is resolved by the {@link AuthInterceptor} into
 * the gRPC context). Both bridge the reactive services to the callback API
 * without blocking: the reactive chain runs off the gRPC thread and completes
 * the observer on its terminal signal.
 */
@Service
public class GatewayIdentityService extends GatewayIdentityGrpc.GatewayIdentityImplBase {

	private final GatewayEnrollmentService enrollment;
	private final GatewayRenewalService renewal;

	public GatewayIdentityService(GatewayEnrollmentService enrollment, GatewayRenewalService renewal) {
		this.enrollment = enrollment;
		this.renewal = renewal;
	}

	@Override
	public void enrollGateway(EnrollGatewayRequest request, StreamObserver<EnrollGatewayResponse> observer) {
		enrollment.enroll(request.getEnrollmentToken(), request.getPkcs10Csr().toByteArray(), request.getGatewayName())
				.subscribe(issued -> complete(observer, toEnrollResponse(issued)),
						error -> observer.onError(GrpcErrors.toStatus(error, "EnrollGateway")));
	}

	@Override
	public void renewGatewayIdentity(RenewGatewayIdentityRequest request,
			StreamObserver<RenewGatewayIdentityResponse> observer) {
		// The interceptor resolved the caller synchronously into the gRPC context; read
		// it before subscribing (the reactive callbacks run on other threads).
		MtlsPeer peer = MtlsContext.peer();
		renewal.renew(peer.gatewayId(), request.getPkcs10Csr().toByteArray(), request.getCurrentGeneration()).subscribe(
				issued -> complete(observer, toRenewResponse(issued)),
				error -> observer.onError(GrpcErrors.toStatus(error, "RenewGatewayIdentity")));
	}

	private static <T> void complete(StreamObserver<T> observer, T value) {
		observer.onNext(value);
		observer.onCompleted();
	}

	private static EnrollGatewayResponse toEnrollResponse(IssuedIdentity issued) {
		return EnrollGatewayResponse.newBuilder().setCertificate(ByteString.copyFrom(issued.certificate()))
				.addAllCaChain(caChain(issued)).setGatewayId(issued.gatewayId().toString())
				.setGeneration(issued.generation()).setNotBeforeEpochSeconds(issued.notBeforeEpochSeconds())
				.setNotAfterEpochSeconds(issued.notAfterEpochSeconds()).build();
	}

	private static RenewGatewayIdentityResponse toRenewResponse(IssuedIdentity issued) {
		return RenewGatewayIdentityResponse.newBuilder().setCertificate(ByteString.copyFrom(issued.certificate()))
				.addAllCaChain(caChain(issued)).setGatewayId(issued.gatewayId().toString())
				.setGeneration(issued.generation()).setNotBeforeEpochSeconds(issued.notBeforeEpochSeconds())
				.setNotAfterEpochSeconds(issued.notAfterEpochSeconds()).build();
	}

	private static Iterable<ByteString> caChain(IssuedIdentity issued) {
		return issued.caChain().stream().map(ByteString::copyFrom).toList();
	}
}
