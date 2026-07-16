package io.sessionlayer.controlplane.machine;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.auth.AuthProperties;
import io.sessionlayer.controlplane.auth.ConsumedAssertionStore;
import io.sessionlayer.controlplane.auth.RateLimiter;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.ServiceAccountCredential;
import io.sessionlayer.controlplane.data.runtime.ServiceAccountCredentialRepository;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Machine identity (Design §5.6, FR-AUTH-12). Issues + revokes rotatable
 * credentials for a {@code service_account} and runs the OAuth
 * client-credentials token endpoint, authenticating the client by
 * {@code private_key_jwt} (preferred), mutual TLS, or a discouraged static
 * secret, then minting a short-lived CP token that resolves to a first-class
 * RBAC principal. Revocation takes effect immediately for <b>new</b> tokens (an
 * already-issued token lives to its short TTL). No raw secret is stored — a
 * client_secret is hashed, a public key stored by DER/fingerprint reference.
 */
@Service
public class MachineIdentityService {

	private static final Logger LOG = LoggerFactory.getLogger(MachineIdentityService.class);
	private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	private final ServiceAccountRepository serviceAccounts;
	private final ServiceAccountCredentialRepository credentials;
	private final MachineTokenSigner signer;
	private final MachineTokenProperties properties;
	private final ConsumedAssertionStore consumedAssertions;
	private final RateLimiter rateLimiter;
	private final AuthProperties authProperties;
	private final AuditEventStore audit;

	public MachineIdentityService(ServiceAccountRepository serviceAccounts,
			ServiceAccountCredentialRepository credentials, MachineTokenSigner signer,
			MachineTokenProperties properties, ConsumedAssertionStore consumedAssertions, RateLimiter rateLimiter,
			AuthProperties authProperties, AuditEventStore audit) {
		this.serviceAccounts = serviceAccounts;
		this.credentials = credentials;
		this.signer = signer;
		this.properties = properties;
		this.consumedAssertions = consumedAssertions;
		this.rateLimiter = rateLimiter;
		this.authProperties = authProperties;
		this.audit = audit;
	}

	public record TokenRequest(String grantType, String clientId, String clientAssertionType, String clientAssertion,
			String clientSecret, String scope) {
	}

	public record IssuedToken(String accessToken, long expiresInSeconds) {
	}

	public record IssuedCredential(ServiceAccountCredential credential, String clientSecret) {
	}

	/** Signals a rejected client-credentials request (fail closed → 400/401). */
	public static final class TokenRequestDenied extends RuntimeException {
		public TokenRequestDenied(String message) {
			super(message);
		}
	}

	// ---- Credential management (admin) -------------------------------------

	public Mono<IssuedCredential> issueCredential(UUID serviceAccountId, String credentialType, String publicKeyPem,
			String jwksUri, String certificateFingerprint, Long ttlSeconds, String actor) {
		return serviceAccounts.findById(serviceAccountId)
				.switchIfEmpty(Mono.error(new IllegalArgumentException("no such service account")))
				.flatMap(sa -> buildCredential(sa, credentialType, publicKeyPem, jwksUri, certificateFingerprint,
						ttlSeconds))
				.flatMap(
						pending -> credentials.save(pending.credential())
								.flatMap(
										saved -> audit
												.record(actor, pending.credential().serviceAccountName(),
														"machine.credential.issue", "success", null, null,
														Map.of("credential_id", saved.id().toString(), "type",
																credentialType))
												.thenReturn(new IssuedCredential(saved, pending.clientSecret()))));
	}

	private Mono<IssuedCredential> buildCredential(ServiceAccount sa, String credentialType, String publicKeyPem,
			String jwksUri, String certificateFingerprint, Long ttlSeconds) {
		Instant now = Instant.now();
		Instant notAfter = ttlSeconds == null ? null : now.plus(Duration.ofSeconds(ttlSeconds));
		return Mono.fromCallable(() -> {
			String secretHash;
			String fingerprint;
			String clientSecret = null;
			switch (credentialType) {
				case "private_key_jwt" -> {
					if (publicKeyPem == null || publicKeyPem.isBlank()) {
						if (jwksUri == null || jwksUri.isBlank()) {
							throw new IllegalArgumentException("private_key_jwt requires publicKeyPem or jwksUri");
						}
						secretHash = "jwks:" + jwksUri; // reference; JWKS verification is future work
						fingerprint = null;
					} else {
						byte[] der = decodePublicKeyDer(publicKeyPem);
						secretHash = Base64.getEncoder().encodeToString(der); // public material (no 'BEGIN'/'PRIVATE
																				// KEY')
						fingerprint = Secrets.sha256Hex(secretHash);
					}
				}
				case "mtls" -> {
					if (certificateFingerprint == null || certificateFingerprint.isBlank()) {
						throw new IllegalArgumentException("mtls requires certificateFingerprint");
					}
					fingerprint = certificateFingerprint;
					secretHash = "mtls:" + certificateFingerprint;
				}
				case "client_secret" -> {
					clientSecret = Secrets.randomToken(24);
					secretHash = Secrets.sha256Hex(clientSecret);
					fingerprint = null;
				}
				default -> throw new IllegalArgumentException("unknown credential type: " + credentialType);
			}
			ServiceAccountCredential credential = ServiceAccountCredential.create(sa.id(), sa.name(), credentialType,
					secretHash, fingerprint, now, notAfter);
			return new IssuedCredential(credential, clientSecret);
		}).subscribeOn(Schedulers.boundedElastic());
	}

	public Mono<ServiceAccountCredential> revokeCredential(UUID serviceAccountId, UUID credentialId, String actor) {
		return credentials.findById(credentialId).filter(c -> c.serviceAccountId().equals(serviceAccountId))
				.flatMap(credential -> {
					if ("revoked".equals(credential.status())) {
						return Mono.just(credential);
					}
					return credentials.save(credential.revoked("admin_revocation", actor, Instant.now()))
							.flatMap(saved -> audit
									.record(actor, credential.serviceAccountName(), "machine.credential.revoke",
											"success", null, null, Map.of("credential_id", credentialId.toString()))
									.thenReturn(saved));
				});
	}

	// ---- Token endpoint ----------------------------------------------------

	public Mono<IssuedToken> issueToken(TokenRequest request, X509Certificate clientCertificate, String sourceIp) {
		if (request.grantType() == null || !request.grantType().equals("client_credentials")) {
			return Mono.error(new TokenRequestDenied("unsupported_grant_type"));
		}
		// Bucket on the non-forgeable source IP, never the attacker-supplied client_id
		// (which would give a fresh unthrottled bucket per request).
		String bucketKey = sourceIp == null || sourceIp.isBlank() ? "no-source" : sourceIp;
		return rateLimiter.tryAcquire("token:" + bucketKey, authProperties.getTokenEndpoint()).flatMap(allowed -> {
			if (!allowed) {
				return Mono.<IssuedToken>error(new TokenRequestDenied("rate_limited"));
			}
			return authenticate(request, clientCertificate).flatMap(this::mint);
		}).onErrorResume(TokenRequestDenied.class,
				denied -> auditDenied(request, sourceIp, denied.getMessage()).then(Mono.error(denied)));
	}

	private Mono<Void> auditDenied(TokenRequest request, String sourceIp, String reason) {
		String actor = request.clientId() != null ? request.clientId() : "unknown";
		return audit
				.record(actor, null, "machine.token.issue", "denied", null, null,
						Map.of("reason", reason, "source_ip", sourceIp == null ? "" : sourceIp))
				.onErrorResume(e -> Mono.empty());
	}

	private Mono<ServiceAccount> authenticate(TokenRequest request, X509Certificate clientCertificate) {
		if (request.clientAssertion() != null && !request.clientAssertion().isBlank()) {
			return authenticatePrivateKeyJwt(request);
		}
		if (clientCertificate != null) {
			return authenticateMtls(clientCertificate);
		}
		if (request.clientId() != null && request.clientSecret() != null) {
			return authenticateClientSecret(request);
		}
		return Mono.error(new TokenRequestDenied("invalid_client"));
	}

	private Mono<ServiceAccount> authenticatePrivateKeyJwt(TokenRequest request) {
		if (!CLIENT_ASSERTION_TYPE.equals(request.clientAssertionType())) {
			return Mono.error(new TokenRequestDenied("invalid_client_assertion_type"));
		}
		ClientAssertions.Claims claims = ClientAssertions.parseUnverified(request.clientAssertion());
		Instant now = Instant.now();
		if (claims == null || claims.subject() == null || claims.jti() == null || claims.expiresAt() == null
		// RFC 7523 §3: iss MUST equal sub (both the client id); aud identifies this AS.
				|| !claims.subject().equals(claims.issuer()) || !claims.audience().contains(properties.getIssuer())
				|| !claims.expiresAt().isAfter(now)
				|| claims.expiresAt().isAfter(now.plus(properties.getMaxAssertionAge()))) {
			return Mono.error(new TokenRequestDenied("invalid_client"));
		}
		return serviceAccounts.findByName(claims.subject())
				.flatMap(sa -> credentials.findByServiceAccountIdAndStatus(sa.id(), "active")
						.filter(c -> "private_key_jwt".equals(c.credentialType()) && c.usable(now))
						.filterWhen(c -> verifyAssertion(request.clientAssertion(), c)).next()
						.flatMap(matched -> consumedAssertions
								.consumeOnce(Secrets.sha256Hex(claims.jti()), claims.subject(), claims.expiresAt())
								.flatMap(fresh -> fresh
										? Mono.just(sa)
										: Mono.error(new TokenRequestDenied("assertion_replayed")))))
				.switchIfEmpty(Mono.error(new TokenRequestDenied("invalid_client")));
	}

	private Mono<Boolean> verifyAssertion(String assertion, ServiceAccountCredential credential) {
		return Mono.fromCallable(() -> {
			try {
				PublicKey key = decodePublicKey(Base64.getDecoder().decode(credential.secretHash()));
				return ClientAssertions.verify(assertion, key);
			} catch (Exception e) {
				return false;
			}
		}).subscribeOn(Schedulers.boundedElastic());
	}

	private Mono<ServiceAccount> authenticateMtls(X509Certificate clientCertificate) {
		Instant now = Instant.now();
		return Mono.fromCallable(() -> CertificateFingerprints.sha256Hex(clientCertificate))
				.subscribeOn(Schedulers.boundedElastic())
				.flatMap(fingerprint -> credentials.findByFingerprintAndStatus(fingerprint, "active"))
				.filter(c -> "mtls".equals(c.credentialType()) && c.usable(now))
				.flatMap(c -> serviceAccounts.findById(c.serviceAccountId()))
				.switchIfEmpty(Mono.error(new TokenRequestDenied("invalid_client")));
	}

	private Mono<ServiceAccount> authenticateClientSecret(TokenRequest request) {
		Instant now = Instant.now();
		String hash = Secrets.sha256Hex(request.clientSecret());
		return credentials.findBySecretHashAndStatus(hash, "active")
				.filter(c -> "client_secret".equals(c.credentialType()) && c.usable(now)
						&& c.serviceAccountName().equals(request.clientId()))
				.flatMap(c -> serviceAccounts.findById(c.serviceAccountId()))
				.switchIfEmpty(Mono.error(new TokenRequestDenied("invalid_client")));
	}

	private Mono<IssuedToken> mint(ServiceAccount serviceAccount) {
		long ttl = properties.getTokenTtl().getSeconds();
		return Mono.fromCallable(() -> signer.mint(serviceAccount.name(), List.of()))
				.subscribeOn(Schedulers.boundedElastic())
				.flatMap(token -> audit
						.record(serviceAccount.name(), null, "machine.token.issue", "success", null, null,
								Map.of("service_account", serviceAccount.name()))
						.thenReturn(new IssuedToken(token, ttl)));
	}

	private static byte[] decodePublicKeyDer(String pem) {
		String base64 = pem.replaceAll("-----BEGIN [^-]+-----", "").replaceAll("-----END [^-]+-----", "")
				.replaceAll("\\s", "");
		byte[] der = Base64.getDecoder().decode(base64);
		decodePublicKey(der); // validate parseability early
		return der;
	}

	private static PublicKey decodePublicKey(byte[] der) {
		for (String algorithm : List.of("RSA", "EC")) {
			try {
				return java.security.KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(der));
			} catch (Exception ignored) {
				// try the next algorithm
			}
		}
		throw new IllegalArgumentException("unsupported public key");
	}
}
