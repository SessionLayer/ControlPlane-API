package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.google.protobuf.ByteString;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.CertificateRequest;
import io.sessionlayer.controlplane.ca.OpenSshCertificate;
import io.sessionlayer.controlplane.ca.SshCertSigner;
import io.sessionlayer.controlplane.ca.cert.CertType;
import io.sessionlayer.controlplane.ca.cert.CertificateParameters;
import io.sessionlayer.controlplane.data.runtime.DeviceFlow;
import io.sessionlayer.controlplane.data.runtime.DeviceFlowRepository;
import io.sessionlayer.controlplane.data.runtime.Pin;
import io.sessionlayer.controlplane.data.runtime.PinRepository;
import io.sessionlayer.controlplane.device.DeviceFlowService;
import io.sessionlayer.controlplane.grpc.v1.BeginDeviceFlowRequest;
import io.sessionlayer.controlplane.grpc.v1.BeginDeviceFlowResponse;
import io.sessionlayer.controlplane.grpc.v1.DeviceFlowStatus;
import io.sessionlayer.controlplane.grpc.v1.OuterLegAuthGrpc;
import io.sessionlayer.controlplane.grpc.v1.PollDeviceFlowRequest;
import io.sessionlayer.controlplane.grpc.v1.PollDeviceFlowResponse;
import io.sessionlayer.controlplane.grpc.v1.ResolveOtpRequest;
import io.sessionlayer.controlplane.grpc.v1.ResolvePinRequest;
import io.sessionlayer.controlplane.grpc.v1.ResolveUserCertRequest;
import io.sessionlayer.controlplane.grpc.v1.ResolvedIdentity;
import io.sessionlayer.controlplane.otp.OtpService;
import io.sessionlayer.controlplane.pin.PinService;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Part D — the outer-leg authentication RPCs (Design §5.1-§5.5, FR-AUTH-1..5/
 * 9/10, FR-CA-2) over the Session-Six services. Proves for each RPC: a valid
 * resolution; the generic {@code resolved = false} for unknown/expired/wrong-
 * source; single-use + rate-limit; the device-flow lifecycle and its throttle;
 * and the mTLS tier (an unauthenticated call is refused before any resolution).
 * Failure never distinguishes a reason on the wire (§7.1, FR-AUTH-16).
 */
class OuterLegAuthIT extends AbstractMtlsIT {

	@Autowired
	private OtpService otpService;
	@Autowired
	private PinService pinService;
	@Autowired
	private PinRepository pinRepository;
	@Autowired
	private DeviceFlowService deviceFlowService;
	@Autowired
	private DeviceFlowRepository deviceFlowRepository;
	@Autowired
	private CaSignerService caSigner;

	private final List<ManagedChannel> channels = new ArrayList<>();
	private EnrolledGateway authedGateway;

	@DynamicPropertySource
	static void limits(DynamicPropertyRegistry registry) {
		// A low max over a long (test-lifetime) window makes the single-use, replay and
		// throttle assertions deterministic without wall-clock window races.
		registry.add("sessionlayer.auth.otp-verify.max", () -> "2");
		registry.add("sessionlayer.auth.otp-verify.window", () -> "30m");
		registry.add("sessionlayer.auth.device-poll.max", () -> "2");
		registry.add("sessionlayer.auth.device-poll.window", () -> "30m");
		// A stable CP origin so the device-flow verification_uri is deterministic.
		registry.add("sessionlayer.oidc.redirect-uri", () -> "https://cp.example.test:8443/v1/auth/callback");
	}

	@AfterEach
	void closeChannels() {
		channels.forEach(AbstractMtlsIT::shutdown);
		channels.clear();
	}

	// ---- ResolveOtp --------------------------------------------------------

	@Test
	void resolveOtpValidThenReplayed() {
		String ip = "10.30.0.1";
		OtpService.IssuedOtp issued = otpService
				.issue("alice@corp", List.of("deploy", "ops"), "10.30.0.0/16", 120, "test").block();

		ResolvedIdentity first = authed().resolveOtp(otpRequest(issued.otp(), ip)).getIdentity();
		assertThat(first.getResolved()).isTrue();
		assertThat(first.getIdentity()).isEqualTo("alice@corp");
		assertThat(first.getPrincipalsList()).containsExactly("deploy", "ops");

		// Single-use: the same code never resolves twice (generic resolved=false).
		assertThat(authed().resolveOtp(otpRequest(issued.otp(), ip)).getIdentity().getResolved()).isFalse();
	}

	@Test
	void resolveOtpWrongSourceDoesNotResolveOrBurn() {
		OtpService.IssuedOtp issued = otpService.issue("bob@corp", List.of("deploy"), "10.31.0.0/16", 120, "test")
				.block();
		// Presented from outside the bound CIDR → resolved=false, and not consumed.
		assertThat(authed().resolveOtp(otpRequest(issued.otp(), "192.0.2.5")).getIdentity().getResolved()).isFalse();
		assertThat(authed().resolveOtp(otpRequest(issued.otp(), "10.31.0.7")).getIdentity().getResolved()).isTrue();
	}

	@Test
	void resolveOtpUnknownCodeIsGenericFalse() {
		assertThat(authed().resolveOtp(otpRequest("NOTAREALOTP2345", "10.32.0.1")).getIdentity().getResolved())
				.isFalse();
	}

	@Test
	void resolveOtpRateLimitSuppressesEvenAValidCode() {
		String ip = "10.33.0.1";
		OtpService.IssuedOtp issued = otpService.issue("carol@corp", List.of("deploy"), "10.33.0.0/16", 120, "test")
				.block();
		// Burn the per-source budget (max=2) with wrong codes, then present the VALID
		// code: it is throttled → resolved=false. Throttle is indistinguishable on the
		// wire from any other failure (§7.1).
		assertThat(authed().resolveOtp(otpRequest("WRONG1", ip)).getIdentity().getResolved()).isFalse();
		assertThat(authed().resolveOtp(otpRequest("WRONG2", ip)).getIdentity().getResolved()).isFalse();
		assertThat(authed().resolveOtp(otpRequest(issued.otp(), ip)).getIdentity().getResolved()).isFalse();
	}

	// ---- ResolvePin --------------------------------------------------------

	@Test
	void resolvePinValidAndWrongSource() {
		String fingerprint = "SHA256:" + Secrets.randomToken(16);
		pinService.create(fingerprint, "dave@corp", "10.40.0.0/16", List.of("deploy", "shell"), 3600, "test").block();

		ResolvedIdentity ok = authed().resolvePin(pinRequest(fingerprint, "10.40.0.9")).getIdentity();
		assertThat(ok.getResolved()).isTrue();
		assertThat(ok.getIdentity()).isEqualTo("dave@corp");
		assertThat(ok.getPrincipalsList()).containsExactly("deploy", "shell");

		// Outside the bound CIDR → generic resolved=false.
		assertThat(authed().resolvePin(pinRequest(fingerprint, "203.0.113.4")).getIdentity().getResolved()).isFalse();
	}

	@Test
	void resolvePinUnknownExpiredAndAmbiguous() {
		assertThat(authed().resolvePin(pinRequest("SHA256:unknown", "10.41.0.1")).getIdentity().getResolved())
				.isFalse();

		// Expired pin (persisted with a past expiry) → resolved=false.
		String expiredFp = "SHA256:" + Secrets.randomToken(16);
		pinRepository.save(Pin.create(expiredFp, "erin@corp", null, List.of("deploy"), Instant.now().minusSeconds(60)))
				.block();
		assertThat(authed().resolvePin(pinRequest(expiredFp, "10.41.0.2")).getIdentity().getResolved()).isFalse();

		// The same fingerprint pinned to two identities (both active, unbound) is
		// ambiguous → resolved=false (fail closed).
		String ambiguousFp = "SHA256:" + Secrets.randomToken(16);
		pinService.create(ambiguousFp, "frank@corp", null, List.of("deploy"), 3600, "test").block();
		pinService.create(ambiguousFp, "grace@corp", null, List.of("deploy"), 3600, "test").block();
		assertThat(authed().resolvePin(pinRequest(ambiguousFp, "10.41.0.3")).getIdentity().getResolved()).isFalse();
	}

	// ---- ResolveUserCert ---------------------------------------------------

	@Test
	void resolveUserCertTrustedResolves() {
		byte[] cert = signUserCert("user", "heidi@corp", List.of("deploy", "ops"), Instant.now().minusSeconds(120),
				Instant.now().plusSeconds(600), null);
		ResolvedIdentity id = authed().resolveUserCert(userCertRequest(cert, "10.50.0.1")).getIdentity();
		assertThat(id.getResolved()).isTrue();
		assertThat(id.getIdentity()).isEqualTo("heidi@corp");
		assertThat(id.getPrincipalsList()).containsExactly("deploy", "ops");
	}

	@Test
	void resolveUserCertWrongCaExpiredAndWrongSourceAreGenericFalse() {
		// Signed by the HOST CA — not a trusted USER CA → resolved=false.
		byte[] wrongCa = signUserCert("host", "ivan@corp", List.of("deploy"), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(600), null);
		assertThat(authed().resolveUserCert(userCertRequest(wrongCa, "10.50.0.2")).getIdentity().getResolved())
				.isFalse();

		// Signed by the user CA but already expired → resolved=false.
		byte[] expired = signUserCert("user", "judy@corp", List.of("deploy"), Instant.now().minusSeconds(7200),
				Instant.now().minusSeconds(3600), null);
		assertThat(authed().resolveUserCert(userCertRequest(expired, "10.50.0.3")).getIdentity().getResolved())
				.isFalse();

		// A cert pinning source-address, presented from outside it → resolved=false.
		byte[] sourcePinned = signUserCert("user", "mallory@corp", List.of("deploy"), Instant.now().minusSeconds(60),
				Instant.now().plusSeconds(600), "10.60.0.0/16");
		assertThat(authed().resolveUserCert(userCertRequest(sourcePinned, "203.0.113.9")).getIdentity().getResolved())
				.isFalse();
		// …and resolves when presented from inside the pinned source.
		assertThat(authed().resolveUserCert(userCertRequest(sourcePinned, "10.60.0.7")).getIdentity().getResolved())
				.isTrue();
	}

	// ---- Device flow -------------------------------------------------------

	@Test
	void beginDeviceFlowReturnsPromptMaterialAndConfiguredVerificationUri() {
		BeginDeviceFlowResponse response = authed()
				.beginDeviceFlow(BeginDeviceFlowRequest.newBuilder().setSourceIp("10.70.0.1").build());
		assertThat(response.getDeviceCode()).isNotBlank();
		assertThat(response.getUserCode()).isNotBlank();
		assertThat(response.getVerificationUri()).isEqualTo("https://cp.example.test:8443/v1/auth/verify");
		assertThat(response.getIntervalSeconds()).isPositive();
		assertThat(response.getExpiresInSeconds()).isPositive();
	}

	@Test
	void deviceFlowLifecyclePendingThenApproved() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("10.71.0.1", "test-binding").block();

		PollDeviceFlowResponse pending = authed().pollDeviceFlow(pollRequest(begun.deviceCode()));
		assertThat(pending.getStatus()).isEqualTo(DeviceFlowStatus.DEVICE_FLOW_STATUS_PENDING);
		assertThat(pending.getIdentity().getResolved()).isFalse();

		deviceFlowService.approve(begun.deviceFlowId(), "nate@corp", "10.71.0.1").block();

		PollDeviceFlowResponse approved = authed().pollDeviceFlow(pollRequest(begun.deviceCode()));
		assertThat(approved.getStatus()).isEqualTo(DeviceFlowStatus.DEVICE_FLOW_STATUS_APPROVED);
		assertThat(approved.getIdentity().getResolved()).isTrue();
		assertThat(approved.getIdentity().getIdentity()).isEqualTo("nate@corp");
	}

	@Test
	void deviceFlowExpiryAndUnknownCodeReportExpired() {
		// A pending flow past its expiry lazily reports EXPIRED on poll.
		String rawDeviceCode = Secrets.randomToken(32);
		String rawUserCode = Secrets.randomUserCode();
		deviceFlowRepository.save(DeviceFlow.create(Secrets.sha256Hex(rawDeviceCode), Secrets.sha256Hex(rawUserCode),
				"binding-x", "10.72.0.1", 5, Instant.now().minusSeconds(60))).block();
		assertThat(authed().pollDeviceFlow(pollRequest(rawDeviceCode)).getStatus())
				.isEqualTo(DeviceFlowStatus.DEVICE_FLOW_STATUS_EXPIRED);

		// An unknown device_code is indistinguishable: EXPIRED, resolved=false.
		PollDeviceFlowResponse unknown = authed().pollDeviceFlow(pollRequest("no-such-device-code"));
		assertThat(unknown.getStatus()).isEqualTo(DeviceFlowStatus.DEVICE_FLOW_STATUS_EXPIRED);
		assertThat(unknown.getIdentity().getResolved()).isFalse();
	}

	@Test
	void throttledPollIsResourceExhausted() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("10.73.0.1", "test-binding").block();
		OuterLegAuthGrpc.OuterLegAuthBlockingStub stub = authed();
		// device-poll max=2 for this device code; the third poll is throttled.
		stub.pollDeviceFlow(pollRequest(begun.deviceCode()));
		stub.pollDeviceFlow(pollRequest(begun.deviceCode()));
		StatusRuntimeException throttled = catchThrowableOfType(StatusRuntimeException.class,
				() -> stub.pollDeviceFlow(pollRequest(begun.deviceCode())));
		assertThat(throttled.getStatus().getCode()).isEqualTo(Status.Code.RESOURCE_EXHAUSTED);
	}

	// ---- Tier --------------------------------------------------------------

	@Test
	void unauthenticatedCallerIsRefused() {
		SslContext noCert = MtlsTestSupport.clientSslContext(caCertificate(), null, null);
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), noCert);
		channels.add(channel);
		OuterLegAuthGrpc.OuterLegAuthBlockingStub stub = OuterLegAuthGrpc.newBlockingStub(channel);
		StatusRuntimeException error = catchThrowableOfType(StatusRuntimeException.class,
				() -> stub.resolveOtp(otpRequest("whatever", "10.80.0.1")));
		assertThat(error.getStatus().getCode()).isEqualTo(Status.Code.UNAUTHENTICATED);
	}

	// ---- helpers -----------------------------------------------------------

	private OuterLegAuthGrpc.OuterLegAuthBlockingStub authed() {
		if (authedGateway == null) {
			// A unique name per test instance: JUnit's per-method lifecycle means each test
			// enrolls its own Gateway (re-enrolling one name would be "already enrolled").
			authedGateway = enroll("gw-outer-" + java.util.UUID.randomUUID());
		}
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), authedGateway.certificate(),
				authedGateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		channels.add(channel);
		return OuterLegAuthGrpc.newBlockingStub(channel);
	}

	/**
	 * Sign a USER certificate for a fresh key with the named CA (optionally
	 * source-pinned).
	 */
	private byte[] signUserCert(String caKind, String identity, List<String> principals, Instant validAfter,
			Instant validBefore, String sourceAddress) {
		SshCertSigner signer = caSigner.activeSigner(caKind).block();
		KeyPair userKey = MtlsTestSupport.generateEcKeyPair();
		TreeMap<String, String> critical = new TreeMap<>(CertificateParameters.BYTE_ORDER);
		if (sourceAddress != null) {
			critical.put("source-address", sourceAddress);
		}
		CertificateParameters params = new CertificateParameters(1L, CertType.USER, identity, principals, validAfter,
				validBefore, critical, new TreeSet<>(CertificateParameters.BYTE_ORDER));
		OpenSshCertificate cert = signer
				.signCertificate(new CertificateRequest((ECPublicKey) userKey.getPublic(), params));
		return cert.blob();
	}

	private static ResolveOtpRequest otpRequest(String otp, String sourceIp) {
		return ResolveOtpRequest.newBuilder().setOtp(otp).setSourceIp(sourceIp).build();
	}

	private static ResolvePinRequest pinRequest(String fingerprint, String sourceIp) {
		return ResolvePinRequest.newBuilder().setPublicKeyFingerprint(fingerprint).setSourceIp(sourceIp).build();
	}

	private static ResolveUserCertRequest userCertRequest(byte[] blob, String sourceIp) {
		return ResolveUserCertRequest.newBuilder().setCertificateBlob(ByteString.copyFrom(blob)).setSourceIp(sourceIp)
				.build();
	}

	private static PollDeviceFlowRequest pollRequest(String deviceCode) {
		return PollDeviceFlowRequest.newBuilder().setDeviceCode(deviceCode).build();
	}
}
