package io.sessionlayer.controlplane.gateway;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.Pkcs10Csrs;
import io.sessionlayer.controlplane.ca.mtls.X509CaBackend;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import io.sessionlayer.controlplane.mtls.GatewayIdentityUri;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Issues a Gateway's <b>serverAuth</b> leaf for its agent-facing TLS listener
 * (S14; Design §9.2/§10.2, FR-CONN-2). The Gateway's identity certificate is
 * stamped {@code clientAuth} (exactly one EKU per leaf, by design), so it
 * cannot serve TLS; Agents must verify the Gateway against an anchor they
 * already hold (the internal mTLS CA) rather than trust it on first use, which
 * needs a genuine serverAuth leaf from that same CA.
 *
 * <p>
 * Authenticated by the caller's current mTLS client certificate (resolved by
 * the interceptor to {@code callerGatewayId}); a locked/inactive identity is
 * refused (fail closed). The <b>CP — not the caller — chooses the subject and
 * SANs</b>, stamping them from the {@code gateway_identity} row it already
 * holds, so a compromised Gateway cannot obtain a server certificate for a name
 * it does not own.
 *
 * <p>
 * There is no generation counter: this is a TLS credential derived from an
 * identity, not an identity. Revocation is by locking the
 * {@code gateway_identity} — reissue is then refused and the outstanding leaf
 * expires on its own (short TTL).
 */
@Service
public class GatewayServerCertificateService {

	private final InternalMtlsCaService mtlsCa;
	private final GatewayIdentityRepository gatewayIdentities;
	private final MtlsProperties properties;
	private final AuditWriter audit;

	public GatewayServerCertificateService(InternalMtlsCaService mtlsCa, GatewayIdentityRepository gatewayIdentities,
			MtlsProperties properties, AuditWriter audit) {
		this.mtlsCa = mtlsCa;
		this.gatewayIdentities = gatewayIdentities;
		this.properties = properties;
		this.audit = audit;
	}

	/**
	 * Issue a serverAuth leaf over the public key in {@code csrDer} for the caller
	 * resolved from its mTLS client certificate. Returns the certificate only — the
	 * Gateway generated this keypair itself and its private half never reaches the
	 * CP (D2/§15).
	 */
	public Mono<IssuedServerCertificate> issue(UUID callerGatewayId, byte[] csrDer) {
		if (callerGatewayId == null) {
			return Mono.error(unauthenticated());
		}
		return gatewayIdentities.findById(callerGatewayId).switchIfEmpty(Mono.error(unauthenticated()))
				.flatMap(identity -> issueFor(identity, csrDer));
	}

	private Mono<IssuedServerCertificate> issueFor(GatewayIdentity identity, byte[] csrDer) {
		// The lock IS the revocation for this leaf: a locked/revoked Gateway gets no
		// reissue and its outstanding server cert expires (fail closed).
		if (!"active".equals(identity.status())) {
			return denied(identity, "inactive");
		}
		return mtlsCa.activeBackend().flatMap(backend -> {
			Instant now = Instant.now();
			Instant notBefore = now.minus(properties.getCertBackdate());
			Instant notAfter = now.plus(properties.getIdentityCertTtl());
			// M7: CSR proof-of-possession verify + ECDSA issuance are CPU-bound — off the
			// reactive event loop. L3: a fresh random serial.
			return Mono
					.fromCallable(() -> backend.issueLeaf(new LeafCertificateSpec(publicKeyOf(csrDer), identity.name(),
							List.of(identity.name()), List.of(GatewayIdentityUri.of(identity.id())), LeafPurpose.SERVER,
							GatewayEnrollmentService.serial(Uuids.v7()), notBefore, notAfter)))
					.subscribeOn(Schedulers.boundedElastic())
					.flatMap(leaf -> audit
							.record(identity.name(), identity.name(), "gateway.server_cert.issue", "success", null,
									null,
									Map.of("fingerprint", CertificateFingerprints.sha256Hex(leaf), "not_after",
											Long.toString(notAfter.getEpochSecond())))
							.thenReturn(toIssued(leaf, backend, identity.name(), notBefore, notAfter)));
		});
	}

	/**
	 * The CSR is a public-key envelope, nothing more: only the certified key (and
	 * its proof of possession) is taken from it. Its subject and any requested SAN
	 * extensions are DISCARDED rather than validated — the CP stamps the name from
	 * the gateway_identity row, so what the caller asked for cannot influence the
	 * issued certificate at all.
	 */
	private static PublicKey publicKeyOf(byte[] csrDer) {
		try {
			return Pkcs10Csrs.parseAndVerify(csrDer).publicKey();
		} catch (Pkcs10Csrs.CsrException e) {
			throw new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT, "invalid CSR");
		}
	}

	private static IssuedServerCertificate toIssued(X509Certificate leaf, X509CaBackend backend, String gatewayName,
			Instant notBefore, Instant notAfter) {
		return new IssuedServerCertificate(GatewayEnrollmentService.der(leaf),
				List.of(GatewayEnrollmentService.der(backend.caCertificate())), gatewayName, notBefore.getEpochSecond(),
				notAfter.getEpochSecond());
	}

	private Mono<IssuedServerCertificate> denied(GatewayIdentity identity, String reason) {
		return audit
				.record(identity.name(), identity.name(), "gateway.server_cert.issue", "denied", null, null,
						Map.of("reason", reason))
				.then(Mono.error(new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
						"server certificate refused")));
	}

	private static GatewayRequestException unauthenticated() {
		return new GatewayRequestException(GatewayRequestException.Reason.UNAUTHENTICATED, "gateway identity unknown");
	}
}
