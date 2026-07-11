package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.AuthApi;
import io.sessionlayer.controlplane.api.model.BeginDeviceFlowRequest;
import io.sessionlayer.controlplane.api.model.CreatePinRequest;
import io.sessionlayer.controlplane.api.model.DeviceFlowResource;
import io.sessionlayer.controlplane.api.model.DeviceFlowStatus;
import io.sessionlayer.controlplane.api.model.IssueOtpRequest;
import io.sessionlayer.controlplane.api.model.IssueServiceAccountCredentialRequest;
import io.sessionlayer.controlplane.api.model.IssuedOtp;
import io.sessionlayer.controlplane.api.model.PinList;
import io.sessionlayer.controlplane.api.model.PinResource;
import io.sessionlayer.controlplane.api.model.ServiceAccountCredentialResource;
import io.sessionlayer.controlplane.api.model.TokenRequest;
import io.sessionlayer.controlplane.api.model.TokenResponse;
import io.sessionlayer.controlplane.device.DeviceFlowService;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.machine.MachineIdentityService.IssuedCredential;
import io.sessionlayer.controlplane.oidc.OidcProperties;
import io.sessionlayer.controlplane.otp.OtpService;
import io.sessionlayer.controlplane.pin.PinService;
import io.sessionlayer.controlplane.platform.PlatformAuthorization;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.platform.PlatformSubject;
import io.sessionlayer.controlplane.security.AuthMethod;
import io.sessionlayer.controlplane.security.CurrentAuthentication;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The secured REST surface for the authentication resources (FR-AUTH-9/10/12,
 * FR-AUTH-17). Implements the contract-first {@link AuthApi}. Admin endpoints
 * are gated by {@link PlatformAuthorization} (default-deny + audited); the
 * machine token endpoint authenticates the client itself; device poll is
 * public. Errors are non-leaking status codes.
 */
@RestController
public class AuthController implements AuthApi {

	private final OtpService otpService;
	private final PinService pinService;
	private final MachineIdentityService machineIdentity;
	private final DeviceFlowService deviceFlowService;
	private final PlatformAuthorization platformAuthorization;
	private final CurrentAuthentication currentAuthentication;
	private final OidcProperties oidcProperties;

	public AuthController(OtpService otpService, PinService pinService, MachineIdentityService machineIdentity,
			DeviceFlowService deviceFlowService, PlatformAuthorization platformAuthorization,
			CurrentAuthentication currentAuthentication, OidcProperties oidcProperties) {
		this.otpService = otpService;
		this.pinService = pinService;
		this.machineIdentity = machineIdentity;
		this.deviceFlowService = deviceFlowService;
		this.platformAuthorization = platformAuthorization;
		this.currentAuthentication = currentAuthentication;
		this.oidcProperties = oidcProperties;
	}

	@Override
	public Mono<ResponseEntity<TokenResponse>> issueMachineToken(Mono<TokenRequest> tokenRequest,
			ServerWebExchange exchange) {
		X509Certificate clientCert = clientCertificate(exchange);
		String sourceIp = sourceIp(exchange);
		return tokenRequest.flatMap(req -> machineIdentity.issueToken(
				new MachineIdentityService.TokenRequest(req.getGrantType(), req.getClientId(),
						req.getClientAssertionType(), req.getClientAssertion(), req.getClientSecret(), req.getScope()),
				clientCert, sourceIp))
				.map(issued -> ResponseEntity
						.ok(new TokenResponse(issued.accessToken(), "Bearer", issued.expiresInSeconds())))
				.onErrorResume(MachineIdentityService.TokenRequestDenied.class,
						denied -> Mono.just(ResponseEntity.status(tokenErrorStatus(denied.getMessage())).build()));
	}

	@Override
	public Mono<ResponseEntity<IssuedOtp>> issueOtp(Mono<IssueOtpRequest> issueOtpRequest, ServerWebExchange exchange) {
		return issueOtpRequest.flatMap(req -> withPermission(PlatformPermissions.USER_MANAGE,
				subject -> otpService
						.issue(req.getIdentity(), req.getAllowedPrincipals(), req.getSourceCidr(), req.getTtlSeconds(),
								subject.identity())
						.map(issued -> ResponseEntity.status(HttpStatus.CREATED)
								.body(new IssuedOtp(issued.id(), issued.otp(), toOffset(issued.expiresAt()))))
						.onErrorResume(IllegalArgumentException.class, badRequest())));
	}

	@Override
	public Mono<ResponseEntity<PinResource>> createPin(Mono<CreatePinRequest> createPinRequest,
			ServerWebExchange exchange) {
		return createPinRequest.flatMap(req -> withPermission(PlatformPermissions.USER_MANAGE,
				subject -> pinService
						.create(req.getFingerprint(), req.getIdentity(), req.getSourceCidr(), req.getPrincipals(),
								req.getTtlSeconds(), subject.identity())
						.map(pin -> ResponseEntity.status(HttpStatus.CREATED).body(toPinResource(pin)))
						.onErrorResume(IllegalArgumentException.class, badRequest())));
	}

	@Override
	public Mono<ResponseEntity<PinList>> listPins(String identity, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.USER_MANAGE, subject -> pinService.listActive(identity)
				.map(AuthController::toPinResource).collectList().map(pins -> ResponseEntity.ok(new PinList(pins))));
	}

	@Override
	public Mono<ResponseEntity<Void>> revokePin(UUID pinId, ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.USER_MANAGE,
				subject -> pinService.revoke(pinId, subject.identity(), "admin_revocation")
						.map(p -> ResponseEntity.noContent().<Void>build())
						.switchIfEmpty(Mono.just(ResponseEntity.notFound().build())));
	}

	@Override
	public Mono<ResponseEntity<ServiceAccountCredentialResource>> issueServiceAccountCredential(UUID serviceAccountId,
			Mono<IssueServiceAccountCredentialRequest> request, ServerWebExchange exchange) {
		return request.flatMap(req -> withPermission(PlatformPermissions.USER_MANAGE, subject -> machineIdentity
				.issueCredential(serviceAccountId, req.getCredentialType().getValue(), req.getPublicKeyPem(),
						req.getJwksUri(), req.getCertificateFingerprint(), req.getTtlSeconds(), subject.identity())
				.map(issued -> ResponseEntity.status(HttpStatus.CREATED).body(toCredentialResource(issued)))
				.onErrorResume(IllegalArgumentException.class, badRequest())));
	}

	@Override
	public Mono<ResponseEntity<Void>> revokeServiceAccountCredential(UUID serviceAccountId, UUID credentialId,
			ServerWebExchange exchange) {
		return withPermission(PlatformPermissions.USER_MANAGE,
				subject -> machineIdentity.revokeCredential(serviceAccountId, credentialId, subject.identity())
						.map(c -> ResponseEntity.noContent().<Void>build())
						.switchIfEmpty(Mono.just(ResponseEntity.notFound().build())));
	}

	@Override
	public Mono<ResponseEntity<DeviceFlowResource>> beginDeviceFlow(Mono<BeginDeviceFlowRequest> request,
			ServerWebExchange exchange) {
		String verificationUri = verificationBase() + "/v1/auth/verify";
		// The contract gates begin on mTLS (the Gateway tied to a real SSH connection);
		// the chain authenticates the caller, and we additionally require the mTLS
		// scheme
		// so a bearer principal cannot forge the SSH source context.
		return currentAuthentication.principal().filter(p -> p.method() == AuthMethod.MTLS).flatMap(p -> request
				.flatMap(req -> deviceFlowService.begin(req.getSourceIp(), req.getConnectionBinding())).map(begun -> {
					DeviceFlowResource resource = new DeviceFlowResource(begun.deviceFlowId(), begun.userCode(),
							verificationUri, begun.deviceCode(), begun.intervalSeconds(), begun.expiresInSeconds());
					resource.setVerificationUriComplete(verificationUri + "?user_code=" + begun.userCode());
					return ResponseEntity.status(HttpStatus.CREATED).body(resource);
				})).switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}

	@Override
	public Mono<ResponseEntity<DeviceFlowStatus>> pollDeviceFlow(
			Mono<io.sessionlayer.controlplane.api.model.PollDeviceFlowRequest> request, ServerWebExchange exchange) {
		return request.flatMap(req -> deviceFlowService.poll(req.getDeviceCode())).map(status -> {
			DeviceFlowStatus body = new DeviceFlowStatus(DeviceFlowStatus.StatusEnum.fromValue(status.status()));
			body.setIdentity(status.identity());
			body.setSourceContextMatch(status.sourceContextMatch());
			return ResponseEntity.ok(body);
		}).switchIfEmpty(Mono.just(ResponseEntity.badRequest().build())).onErrorResume(
				DeviceFlowService.RateLimited.class,
				e -> Mono.just(ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).build()));
	}

	// ---- helpers -----------------------------------------------------------

	private <T> Mono<ResponseEntity<T>> withPermission(String permission,
			Function<PlatformSubject, Mono<ResponseEntity<T>>> action) {
		return currentAuthentication.subject()
				.flatMap(subject -> platformAuthorization.authorize(subject, permission, null)
						.flatMap(decision -> decision.allowed()
								? action.apply(subject)
								: Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).<T>build())))
				.switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.FORBIDDEN).build()));
	}

	private static <T> Function<Throwable, Mono<ResponseEntity<T>>> badRequest() {
		return e -> Mono.just(ResponseEntity.badRequest().build());
	}

	private static HttpStatus tokenErrorStatus(String reason) {
		return switch (reason) {
			case "rate_limited" -> HttpStatus.TOO_MANY_REQUESTS;
			case "unsupported_grant_type" -> HttpStatus.BAD_REQUEST;
			default -> HttpStatus.UNAUTHORIZED;
		};
	}

	private static PinResource toPinResource(io.sessionlayer.controlplane.data.runtime.Pin pin) {
		PinResource resource = new PinResource(pin.id(), pin.fingerprint(), pin.identity(), pin.principals(),
				toOffset(pin.expiresAt()));
		resource.setSourceCidr(pin.sourceCidr());
		resource.setRevokedAt(pin.revokedAt() == null ? null : toOffset(pin.revokedAt()));
		return resource;
	}

	private static ServiceAccountCredentialResource toCredentialResource(IssuedCredential issued) {
		var credential = issued.credential();
		ServiceAccountCredentialResource resource = new ServiceAccountCredentialResource(credential.id(),
				credential.serviceAccountId(), credential.credentialType(), credential.status(),
				toOffset(credential.issuedAt()));
		resource.setFingerprint(credential.fingerprint());
		resource.setClientSecret(issued.clientSecret());
		resource.setNotAfter(credential.notAfter() == null ? null : toOffset(credential.notAfter()));
		return resource;
	}

	private static X509Certificate clientCertificate(ServerWebExchange exchange) {
		SslInfo ssl = exchange.getRequest().getSslInfo();
		if (ssl == null || ssl.getPeerCertificates() == null || ssl.getPeerCertificates().length == 0) {
			return null;
		}
		return ssl.getPeerCertificates()[0];
	}

	private static String sourceIp(ServerWebExchange exchange) {
		var remote = exchange.getRequest().getRemoteAddress();
		return remote == null || remote.getAddress() == null ? null : remote.getAddress().getHostAddress();
	}

	/**
	 * The CP public origin for the verification URL — derived from the configured
	 * OIDC {@code redirect-uri} (not the request Host header, which a proxy may
	 * forward verbatim, aiding phishing). Falls back to the redirect-uri as-is.
	 */
	private String verificationBase() {
		String redirect = oidcProperties.getRedirectUri();
		if (redirect == null || redirect.isBlank()) {
			return "";
		}
		try {
			java.net.URI uri = java.net.URI.create(redirect);
			return uri.getScheme() + "://" + uri.getAuthority();
		} catch (RuntimeException malformed) {
			return "";
		}
	}

	private static OffsetDateTime toOffset(Instant instant) {
		return instant.atOffset(ZoneOffset.UTC);
	}
}
