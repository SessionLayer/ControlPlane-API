package io.sessionlayer.controlplane.grpc;

import io.grpc.stub.StreamObserver;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.breakglass.BreakglassResolutionService;
import io.sessionlayer.controlplane.device.DeviceFlowService;
import io.sessionlayer.controlplane.grpc.v1.BeginDeviceFlowRequest;
import io.sessionlayer.controlplane.grpc.v1.BeginDeviceFlowResponse;
import io.sessionlayer.controlplane.grpc.v1.BreakglassResolution;
import io.sessionlayer.controlplane.grpc.v1.DeviceFlowStatus;
import io.sessionlayer.controlplane.grpc.v1.OuterLegAuthGrpc;
import io.sessionlayer.controlplane.grpc.v1.PollDeviceFlowRequest;
import io.sessionlayer.controlplane.grpc.v1.PollDeviceFlowResponse;
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassCodeRequest;
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassCodeResponse;
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassKeyRequest;
import io.sessionlayer.controlplane.grpc.v1.ResolveBreakglassKeyResponse;
import io.sessionlayer.controlplane.grpc.v1.ResolveOtpRequest;
import io.sessionlayer.controlplane.grpc.v1.ResolveOtpResponse;
import io.sessionlayer.controlplane.grpc.v1.ResolvePinRequest;
import io.sessionlayer.controlplane.grpc.v1.ResolvePinResponse;
import io.sessionlayer.controlplane.grpc.v1.ResolveUserCertRequest;
import io.sessionlayer.controlplane.grpc.v1.ResolveUserCertResponse;
import io.sessionlayer.controlplane.grpc.v1.ResolvedIdentity;
import io.sessionlayer.controlplane.mtls.MtlsContext;
import io.sessionlayer.controlplane.mtls.MtlsPeer;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import io.sessionlayer.controlplane.oidc.OidcProperties;
import io.sessionlayer.controlplane.otp.OtpService;
import io.sessionlayer.controlplane.pin.PinService;
import io.sessionlayer.controlplane.usercert.UserCertResolver;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * The outer-leg AUTHENTICATION gRPC service (Part D, Design §5.1-§5.5,
 * FR-AUTH-1..5/9/10, FR-CA-2), implemented over the Session-Six services (OTP,
 * pins, device flow, user-facing CA). mTLS-required tier: the
 * {@link AuthInterceptor} authenticates the calling Gateway; these RPCs are not
 * bootstrap methods, so an unauthenticated call is refused
 * {@code UNAUTHENTICATED} before it reaches here.
 *
 * <p>
 * AUTHENTICATION ONLY (invariant I2): every RPC answers "who is this?" and
 * never grants access — the Gateway still calls {@code Authorization.Authorize}
 * for the target node. Resolution failure is the single generic
 * {@code resolved = false} for ANY reason (§7.1, FR-AUTH-16); reasons go only
 * to the decision log. The CP maps identity → principals; a client-claimed
 * principal is never echoed.
 */
@Service
public class OuterLegAuthService extends OuterLegAuthGrpc.OuterLegAuthImplBase {

	private final UserCertResolver userCertResolver;
	private final PinService pinService;
	private final OtpService otpService;
	private final DeviceFlowService deviceFlowService;
	private final BreakglassResolutionService breakglassResolution;
	private final OidcProperties oidcProperties;
	private final MtlsProperties properties;

	public OuterLegAuthService(UserCertResolver userCertResolver, PinService pinService, OtpService otpService,
			DeviceFlowService deviceFlowService, BreakglassResolutionService breakglassResolution,
			OidcProperties oidcProperties, MtlsProperties properties) {
		this.userCertResolver = userCertResolver;
		this.pinService = pinService;
		this.otpService = otpService;
		this.deviceFlowService = deviceFlowService;
		this.breakglassResolution = breakglassResolution;
		this.oidcProperties = oidcProperties;
		this.properties = properties;
	}

	@Override
	public void resolveUserCert(ResolveUserCertRequest request, StreamObserver<ResolveUserCertResponse> observer) {
		Mono<ResolveUserCertResponse> result = userCertResolver
				.resolve(request.getCertificateBlob().toByteArray(), blankToNull(request.getSourceIp()))
				.map(r -> ResolveUserCertResponse.newBuilder()
						.setIdentity(resolved(r.identity(), r.principals(), List.of())).build())
				.defaultIfEmpty(ResolveUserCertResponse.newBuilder().setIdentity(unresolved()).build());
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "ResolveUserCert");
	}

	@Override
	public void resolvePin(ResolvePinRequest request, StreamObserver<ResolvePinResponse> observer) {
		Mono<ResolvePinResponse> result = pinService
				.resolveForSource(request.getPublicKeyFingerprint(), blankToNull(request.getSourceIp()))
				.map(r -> ResolvePinResponse.newBuilder().setIdentity(resolved(r.identity(), r.principals(), List.of()))
						.build())
				.defaultIfEmpty(ResolvePinResponse.newBuilder().setIdentity(unresolved()).build());
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "ResolvePin");
	}

	@Override
	public void resolveOtp(ResolveOtpRequest request, StreamObserver<ResolveOtpResponse> observer) {
		// request.getOtp() is a SECRET (echo-off keyboard-interactive) — never logged.
		Mono<ResolveOtpResponse> result = otpService
				.validate(request.getOtp(), blankToNull(request.getSourceIp())).map(r -> ResolveOtpResponse.newBuilder()
						.setIdentity(resolved(r.identity(), r.principals(), List.of())).build())
				.defaultIfEmpty(ResolveOtpResponse.newBuilder().setIdentity(unresolved()).build());
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "ResolveOtp");
	}

	@Override
	public void beginDeviceFlow(BeginDeviceFlowRequest request, StreamObserver<BeginDeviceFlowResponse> observer) {
		String verificationUri = oidcProperties.verificationBaseUrl() + "/v1/auth/verify";
		// connectionBinding is a reserved field no path reads (RC-1): the real 1:1
		// device_code<->connection binding is device_code secrecy (per-connection,
		// hashed at rest, never logged, §15). Minted for schema parity, not relied on.
		String connectionBinding = Secrets.randomToken(32);
		Mono<BeginDeviceFlowResponse> result = deviceFlowService
				.begin(blankToNull(request.getSourceIp()), connectionBinding)
				.map(begun -> BeginDeviceFlowResponse.newBuilder().setDeviceCode(begun.deviceCode())
						.setUserCode(begun.userCode()).setVerificationUri(verificationUri)
						.setIntervalSeconds(begun.intervalSeconds())
						.setExpiresInSeconds(Math.toIntExact(begun.expiresInSeconds())).build());
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "BeginDeviceFlow");
	}

	@Override
	public void pollDeviceFlow(PollDeviceFlowRequest request, StreamObserver<PollDeviceFlowResponse> observer) {
		// An unknown device_code reports EXPIRED (generic, no existence disclosure); a
		// throttled poll surfaces as RESOURCE_EXHAUSTED via GrpcErrors.
		Mono<PollDeviceFlowResponse> result = deviceFlowService.poll(request.getDeviceCode())
				.map(OuterLegAuthService::toPollResponse).defaultIfEmpty(PollDeviceFlowResponse.newBuilder()
						.setStatus(DeviceFlowStatus.DEVICE_FLOW_STATUS_EXPIRED).setIdentity(unresolved()).build());
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "PollDeviceFlow");
	}

	private static PollDeviceFlowResponse toPollResponse(DeviceFlowService.Status status) {
		DeviceFlowStatus wire = switch (status.status()) {
			case "pending" -> DeviceFlowStatus.DEVICE_FLOW_STATUS_PENDING;
			case "authorized", "approved" -> DeviceFlowStatus.DEVICE_FLOW_STATUS_APPROVED;
			case "denied" -> DeviceFlowStatus.DEVICE_FLOW_STATUS_DENIED;
			// expired or any unexpected state → generic EXPIRED (fail closed, no leak).
			default -> DeviceFlowStatus.DEVICE_FLOW_STATUS_EXPIRED;
		};
		boolean approved = wire == DeviceFlowStatus.DEVICE_FLOW_STATUS_APPROVED && status.identity() != null
				&& !status.identity().isBlank();
		// Device-flow logins carry no cert/OTP principal reducer — RBAC alone decides
		// the logins (principals empty). Groups are not persisted on the device_flow
		// row, so they are empty here; group-based selectors for device-flow logins
		// would require persisting the OIDC groups captured at the verification page.
		ResolvedIdentity identity = approved ? resolved(status.identity(), List.of(), List.of()) : unresolved();
		return PollDeviceFlowResponse.newBuilder().setStatus(wire).setIdentity(identity).build();
	}

	@Override
	public void resolveBreakglassKey(ResolveBreakglassKeyRequest request,
			StreamObserver<ResolveBreakglassKeyResponse> observer) {
		// FIDO2 proof-of-possession (the sk-auth challenge/signature + any user
		// verification) is proven UPSTREAM by the Gateway's SSH handshake before this
		// RPC; the CP resolves identity from the PUBLIC key blob only, symmetric with
		// ResolvePin. The AUTHENTICATED caller is the mTLS peer (AuthInterceptor),
		// never a
		// field; the minted token binds to it so a break-glass Authorize can only come
		// from this GW.
		UUID caller = callerGatewayId();
		Mono<ResolveBreakglassKeyResponse> result = breakglassResolution
				.resolveKey(request.getSkPublicKeyBlob().toByteArray(), blankToNull(request.getSourceIp()),
						parseUuid(request.getNodeId()), caller)
				.map(r -> ResolveBreakglassKeyResponse.newBuilder().setResolution(toResolution(r)).build())
				.defaultIfEmpty(
						ResolveBreakglassKeyResponse.newBuilder().setResolution(unresolvedBreakglass()).build());
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "ResolveBreakglassKey");
	}

	@Override
	public void resolveBreakglassCode(ResolveBreakglassCodeRequest request,
			StreamObserver<ResolveBreakglassCodeResponse> observer) {
		// request.getCode() is a SECRET (keyboard-interactive, echo off) — NEVER
		// logged.
		UUID caller = callerGatewayId();
		Mono<ResolveBreakglassCodeResponse> result = breakglassResolution
				.resolveCode(request.getCode(), blankToNull(request.getSourceIp()), parseUuid(request.getNodeId()),
						caller)
				.map(r -> ResolveBreakglassCodeResponse.newBuilder().setResolution(toResolution(r)).build())
				.defaultIfEmpty(
						ResolveBreakglassCodeResponse.newBuilder().setResolution(unresolvedBreakglass()).build());
		ReactiveBridge.forward(result, observer, properties.getRpcTimeout(), "ResolveBreakglassCode");
	}

	private static UUID callerGatewayId() {
		MtlsPeer peer = MtlsContext.peer();
		return peer == null ? null : peer.gatewayId();
	}

	private static BreakglassResolution toResolution(BreakglassResolutionService.Resolution resolution) {
		return BreakglassResolution.newBuilder()
				.setIdentity(resolved(resolution.identity(), resolution.principals(), List.of()))
				.setBreakglassToken(resolution.token()).build();
	}

	private static BreakglassResolution unresolvedBreakglass() {
		return BreakglassResolution.newBuilder().setIdentity(unresolved()).build();
	}

	private static UUID parseUuid(String value) {
		if (value == null || value.isBlank()) {
			return null; // an empty node id is tolerated (a fleet-scoped credential)
		}
		try {
			return UUID.fromString(value);
		} catch (IllegalArgumentException notAUuid) {
			return null;
		}
	}

	private static ResolvedIdentity resolved(String identity, List<String> principals, List<String> groups) {
		return ResolvedIdentity.newBuilder().setResolved(true).setIdentity(identity).addAllPrincipals(principals)
				.addAllGroups(groups).build();
	}

	private static ResolvedIdentity unresolved() {
		return ResolvedIdentity.newBuilder().setResolved(false).build();
	}

	private static String blankToNull(String value) {
		return value == null || value.isBlank() ? null : value;
	}
}
