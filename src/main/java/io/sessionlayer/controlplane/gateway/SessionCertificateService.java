package io.sessionlayer.controlplane.gateway;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.CertificateRequest;
import io.sessionlayer.controlplane.ca.OpenSshCertificate;
import io.sessionlayer.controlplane.ca.SshCertSigner;
import io.sessionlayer.controlplane.ca.cert.CertificateParameters;
import io.sessionlayer.controlplane.ca.cert.CertificateProfiles;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.SessionSigningToken;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Signs a session's inner-leg SSH certificate over gRPC with per-RPC,
 * session-bound authorization (Part C, Design §15). The mTLS interceptor
 * authenticates the calling Gateway; here the CP re-checks the caller's
 * {@code gateway_identity} is active + unlocked, consumes the single-use
 * session token (bound to THIS gateway and its session/node/principal), then
 * mints the inner-leg cert from the S3 session CA over the Gateway-presented
 * <b>public key</b> and returns the certificate only. The CP never receives or
 * stores an inner private key (D2/FR-CA-3). Every authorization failure is
 * generic.
 */
@Service
public class SessionCertificateService {

	private final SessionSigningTokenService tokenService;
	private final CaSignerService caSigner;
	private final GatewayIdentityRepository gatewayIdentities;
	private final AuditEventStore audit;

	public SessionCertificateService(SessionSigningTokenService tokenService, CaSignerService caSigner,
			GatewayIdentityRepository gatewayIdentities, AuditEventStore audit) {
		this.tokenService = tokenService;
		this.caSigner = caSigner;
		this.gatewayIdentities = gatewayIdentities;
		this.audit = audit;
	}

	/**
	 * Sign the inner-leg cert authorised by {@code rawToken} for the caller
	 * {@code callerGatewayId}. Fails closed (generic) on an inactive caller, a
	 * cross-gateway / cross-session / expired / replayed token, or a context that
	 * disagrees with the token. A malformed subject key is an
	 * {@code INVALID_ARGUMENT}.
	 */
	public Mono<SignedInnerCert> sign(UUID callerGatewayId, String presentedFingerprint, String rawToken,
			byte[] subjectPublicKeyBlob, SignRequestContext context) {
		ECPublicKey subjectKey;
		try {
			subjectKey = SshEcdsaPublicKeys.parse(subjectPublicKeyBlob);
		} catch (RuntimeException malformed) {
			return Mono.error(new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT,
					"invalid subject public key"));
		}
		return requireAuthorizedGateway(callerGatewayId, presentedFingerprint)
				.then(tokenService.consume(rawToken, callerGatewayId, context))
				.flatMap(token -> caSigner.activeSigner("session")
						// M7: OpenSSH cert assembly + ECDSA sign is CPU-bound — off the event loop.
						.flatMap(signer -> Mono.fromCallable(() -> mint(signer, subjectKey, token))
								.subscribeOn(Schedulers.boundedElastic()))
						.flatMap(signed -> audit
								.record(callerGatewayId.toString(), token.principal(), "session.sign", "success",
										token.sessionId(), token.nodeId(), Map.of("key_id", signed.keyId()))
								.thenReturn(signed)))
				// M4 / FR-AUD-7: every fail-closed denial on the signing path is audited
				// (generic to the client; the category reason + caller id stay server-side).
				.onErrorResume(GatewayRequestException.class,
						denial -> audit
								.record(callerGatewayId == null ? "unknown" : callerGatewayId.toString(), null,
										"session.sign", "denied", null, null, Map.of("reason", denial.reason().name()))
								.then(Mono.error(denial)));
	}

	// M6: the caller's identity must be active AND the presented client cert must
	// pin to
	// the identity's current or previous fingerprint (a superseded/stolen cert is
	// refused).
	private Mono<GatewayIdentity> requireAuthorizedGateway(UUID callerGatewayId, String presentedFingerprint) {
		if (callerGatewayId == null || presentedFingerprint == null) {
			return Mono.error(denied());
		}
		return gatewayIdentities.findById(callerGatewayId).switchIfEmpty(Mono.error(denied())).flatMap(identity -> {
			boolean active = "active".equals(identity.status());
			boolean pinned = presentedFingerprint.equals(identity.fingerprint())
					|| presentedFingerprint.equals(identity.prevFingerprint());
			return active && pinned ? Mono.just(identity) : Mono.error(denied());
		});
	}

	// Compute the cert parameters ONCE, sign over the presented public key, and
	// derive the response validity from the same parameters (no re-clocking).
	private static SignedInnerCert mint(SshCertSigner signer, ECPublicKey subjectKey, SessionSigningToken token) {
		// Minimal CP-internal path: the human "identity" component of the key id is the
		// principal (S5/S8 will supply the real human identity distinct from the Linux
		// login). key_id = session_id + identity (Design §12.2 / FR-CA-5).
		String principal = token.principal();
		Set<String> capabilities = new HashSet<>(token.capabilities());
		CertificateParameters params = CertificateProfiles.innerLegSessionCert(token.sessionId().toString(), principal,
				principal, token.sourceAddress(), capabilities, serial(token.id()), Instant.now());
		OpenSshCertificate cert = signer.signCertificate(new CertificateRequest(subjectKey, params));
		return new SignedInnerCert(cert.certificateLine(), cert.blob(), cert.keyId(),
				params.validAfter().getEpochSecond(), params.validBefore().getEpochSecond());
	}

	private static long serial(UUID id) {
		return id.getMostSignificantBits() & Long.MAX_VALUE;
	}

	private static GatewayRequestException denied() {
		return new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
				"session signing request refused");
	}
}
