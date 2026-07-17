package io.sessionlayer.controlplane.gateway;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.CaSignerService;
import io.sessionlayer.controlplane.ca.CertificateRequest;
import io.sessionlayer.controlplane.ca.OpenSshCertificate;
import io.sessionlayer.controlplane.ca.SshCertSigner;
import io.sessionlayer.controlplane.ca.cert.CertificateParameters;
import io.sessionlayer.controlplane.ca.cert.CertificateProfiles;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Signs the Gateway's OUTER SSH host certificate for the ProxyJump host-cert
 * MITM path (S16, Design §9.3/§11; FR-ADDR-1). On that path the Gateway
 * terminates the client's inner SSH hop and must present a HOST certificate
 * signed by the host CA so a stock OpenSSH client that installed one
 * {@code @cert-authority} line accepts the Gateway as the target node with NO
 * TOFU.
 *
 * <p>
 * Unlike {@link SessionCertificateService} this is NOT session-bound (a host
 * cert is presented before the inner hop authenticates, so there is no session
 * token yet). It is authorized purely by the caller's Gateway mTLS identity:
 * mirrors {@link GatewayServerCertificateService} — the interceptor resolves
 * the caller and here the CP re-checks the {@code gateway_identity} is active +
 * unlocked (the lock IS the revocation; there is no generation counter). The CP
 * chooses the {@code key_id} from the identity row; the caller only supplies
 * the host public key and the host principals, both validated.
 *
 * <p>
 * KEY CUSTODY (D2/§9.3): the Gateway generates the host keypair locally and
 * sends only the public key; the CP returns a certificate only.
 */
@Service
public class GatewayHostCertificateService {

	// A host principal is a hostname the client dials; bound its length (DNS max)
	// and count so a hostile caller cannot inflate the cert or the audit record.
	private static final int MAX_PRINCIPAL_LENGTH = 253;
	private static final int MAX_PRINCIPALS = 32;

	private final CaSignerService caSigner;
	private final GatewayIdentityRepository gatewayIdentities;
	private final MtlsProperties properties;
	private final AuditEventStore audit;

	public GatewayHostCertificateService(CaSignerService caSigner, GatewayIdentityRepository gatewayIdentities,
			MtlsProperties properties, AuditEventStore audit) {
		this.caSigner = caSigner;
		this.gatewayIdentities = gatewayIdentities;
		this.properties = properties;
		this.audit = audit;
	}

	/**
	 * Sign a short-lived HOST cert over {@code hostPublicKeyWire} (an OpenSSH
	 * wire-encoded ECDSA P-256 blob) for the caller resolved from its mTLS client
	 * certificate. Fails closed (generic) on an inactive/unknown caller; a
	 * malformed key or an empty/oversize/blank principal is an
	 * {@code INVALID_ARGUMENT}.
	 */
	public Mono<IssuedHostCertificate> sign(UUID callerGatewayId, byte[] hostPublicKeyWire, List<String> principals) {
		if (callerGatewayId == null) {
			return Mono.error(unauthenticated());
		}
		List<String> validated;
		ECPublicKey hostKey;
		try {
			validated = validatePrincipals(principals);
			hostKey = SshEcdsaPublicKeys.parse(hostPublicKeyWire);
		} catch (GatewayRequestException invalid) {
			return Mono.error(invalid);
		} catch (RuntimeException malformed) {
			return Mono.error(
					new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT, "invalid host key"));
		}
		return gatewayIdentities.findById(callerGatewayId).switchIfEmpty(Mono.error(unauthenticated()))
				.flatMap(identity -> signFor(identity, hostKey, validated));
	}

	private Mono<IssuedHostCertificate> signFor(GatewayIdentity identity, ECPublicKey hostKey,
			List<String> principals) {
		// The lock IS the revocation: a locked/revoked Gateway gets no reissue and its
		// outstanding host cert expires on its short TTL (fail closed).
		if (!"active".equals(identity.status())) {
			return denied(identity, "inactive");
		}
		return caSigner.activeSigner("host").flatMap(signer -> {
			Instant now = Instant.now();
			Instant notBefore = now.minus(properties.getCertBackdate());
			Instant notAfter = now.plus(properties.getHostCertTtl());
			// OpenSSH cert assembly + ECDSA sign is CPU-bound — off the reactive event
			// loop.
			return Mono.fromCallable(() -> mint(signer, identity.name(), hostKey, principals, notBefore, notAfter))
					.subscribeOn(
							Schedulers.boundedElastic())
					.flatMap(cert -> audit.record(identity.name(), identity.name(), "gateway.host_cert.sign", "success",
							null, null, Map.of("principals", String.join(",", principals), "not_after",
									Long.toString(notAfter.getEpochSecond())))
							.thenReturn(cert));
		})
				// Signer-unavailable (NFR-3 fail-closed) is not a GatewayRequestException;
				// audit it distinctly so a CA-availability incident is forensically visible.
				.onErrorResume(CaSignerService.NoSignerAvailable.class,
						unavailable -> audit.record(identity.name(), identity.name(), "gateway.host_cert.sign",
								"denied", null, null, Map.of("reason", "ca_unavailable"))
								.then(Mono.error(unavailable)));
	}

	private static IssuedHostCertificate mint(SshCertSigner signer, String gatewayName, ECPublicKey hostKey,
			List<String> principals, Instant notBefore, Instant notAfter) {
		CertificateParameters params = CertificateProfiles.gatewayHostCert(gatewayName, principals, notBefore, notAfter,
				serial());
		OpenSshCertificate cert = signer.signCertificate(new CertificateRequest(hostKey, params));
		return new IssuedHostCertificate(cert.certificateLine(), cert.blob(), notBefore.getEpochSecond(),
				notAfter.getEpochSecond());
	}

	private static List<String> validatePrincipals(List<String> principals) {
		if (principals == null || principals.isEmpty()) {
			throw new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT,
					"at least one host principal is required");
		}
		if (principals.size() > MAX_PRINCIPALS) {
			throw new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT,
					"too many host principals");
		}
		for (String principal : principals) {
			if (principal == null || principal.isBlank() || principal.length() > MAX_PRINCIPAL_LENGTH
					|| hasControlChars(principal)) {
				throw new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT,
						"invalid host principal");
			}
		}
		return List.copyOf(principals);
	}

	private static boolean hasControlChars(String value) {
		return value.chars().anyMatch(c -> c < 0x20 || c == 0x7f);
	}

	private static long serial() {
		UUID id = Uuids.v7();
		return id.getMostSignificantBits() & Long.MAX_VALUE;
	}

	private Mono<IssuedHostCertificate> denied(GatewayIdentity identity, String reason) {
		return audit
				.record(identity.name(), identity.name(), "gateway.host_cert.sign", "denied", null, null,
						Map.of("reason", reason))
				.then(Mono.error(new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
						"host certificate refused")));
	}

	private static GatewayRequestException unauthenticated() {
		return new GatewayRequestException(GatewayRequestException.Reason.UNAUTHENTICATED, "gateway identity unknown");
	}
}
