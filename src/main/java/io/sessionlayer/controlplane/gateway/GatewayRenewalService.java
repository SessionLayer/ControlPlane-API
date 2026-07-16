package io.sessionlayer.controlplane.gateway;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.ca.mtls.InternalMtlsCaService;
import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.Pkcs10Csrs;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.mtls.CertificateFingerprints;
import io.sessionlayer.controlplane.mtls.GatewayIdentityUri;
import io.sessionlayer.controlplane.mtls.MtlsProperties;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Renews a Gateway's mTLS identity (Part B, FR-JOIN-4). Authenticated by the
 * caller's current mTLS client certificate (resolved by the interceptor to
 * {@code callerGatewayId}); a locked/revoked identity is refused (fail closed).
 * The CP issues {@code current_generation + 1} and enforces monotonicity: a
 * declared generation that does not match the stored one is a security event
 * (refused + flagged, §8.2), and a concurrent renewal loses the
 * {@code @Version} optimistic race (also refused). Renew-ahead is the Gateway's
 * loop; the CP only issues.
 */
@Service
public class GatewayRenewalService {

	private final InternalMtlsCaService mtlsCa;
	private final GatewayIdentityRepository gatewayIdentities;
	private final MtlsProperties properties;
	private final AuditEventStore audit;

	public GatewayRenewalService(InternalMtlsCaService mtlsCa, GatewayIdentityRepository gatewayIdentities,
			MtlsProperties properties, AuditEventStore audit) {
		this.mtlsCa = mtlsCa;
		this.gatewayIdentities = gatewayIdentities;
		this.properties = properties;
		this.audit = audit;
	}

	/**
	 * Rotate the caller's identity certificate and increment the generation.
	 * {@code presentedFingerprint} is the SHA-256 of the client certificate the
	 * caller presented on this mTLS call (resolved by the interceptor / handler);
	 * it must pin to the identity's current or previous fingerprint (M6).
	 */
	public Mono<IssuedIdentity> renew(UUID callerGatewayId, String presentedFingerprint, byte[] csrDer,
			long currentGeneration) {
		if (callerGatewayId == null) {
			return Mono.error(unauthenticated());
		}
		return gatewayIdentities.findById(callerGatewayId).switchIfEmpty(Mono.error(unauthenticated()))
				.flatMap(identity -> renewFor(identity, presentedFingerprint, csrDer, currentGeneration));
	}

	private Mono<IssuedIdentity> renewFor(GatewayIdentity identity, String presentedFingerprint, byte[] csrDer,
			long currentGeneration) {
		if (!"active".equals(identity.status())) {
			return denied(identity, "inactive");
		}
		// M6: the presented client cert must be the current or previous-generation cert
		// —
		// a superseded/stolen prior cert cannot renew. {current, previous} tolerates
		// the
		// renew-ahead overlap.
		if (!fingerprintPins(identity, presentedFingerprint)) {
			return denied(identity, "fingerprint_mismatch");
		}
		Pkcs10Csrs.ParsedCsr csr;
		try {
			csr = Pkcs10Csrs.parseAndVerify(csrDer);
		} catch (Pkcs10Csrs.CsrException e) {
			return Mono
					.error(new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT, "invalid CSR"));
		}
		if (!identity.name().equals(csr.commonName())) {
			return Mono.error(new GatewayRequestException(GatewayRequestException.Reason.INVALID_ARGUMENT,
					"CSR subject does not match identity"));
		}
		if (currentGeneration != identity.generation()) {
			// §8.2: a generation mismatch is a security event — flag it (audit) and refuse,
			// never a silent pass. The full auto-lock fan-out is S10.
			return audit.record(identity.name(), identity.name(), "gateway.renew.generation_mismatch", "failure", null,
					null, Map.of("expected", Long.toString(identity.generation()), "presented",
							Long.toString(currentGeneration)))
					.then(Mono.error(generationMismatch()));
		}
		long newGeneration = identity.generation() + 1;
		return mtlsCa.activeBackend().flatMap(backend -> {
			Instant now = Instant.now();
			Instant notBefore = now.minus(properties.getCertBackdate());
			Instant notAfter = now.plus(properties.getIdentityCertTtl());
			// M7: X.509 issuance (ECDSA sign) is CPU-bound — off the reactive event loop.
			return Mono
					.fromCallable(() -> backend.issueLeaf(new LeafCertificateSpec(csr.publicKey(), identity.name(),
							List.of(identity.name()), List.of(GatewayIdentityUri.of(identity.id())), LeafPurpose.CLIENT,
							GatewayEnrollmentService.serial(Uuids.v7()), notBefore, notAfter)))
					.subscribeOn(Schedulers.boundedElastic()).flatMap(leaf -> {
						String fingerprint = CertificateFingerprints.sha256Hex(leaf);
						// M6: record the OUTGOING fingerprint as prev_fingerprint so the pin
						// tolerates the renew-ahead overlap until the next renew.
						GatewayIdentity renewed = new GatewayIdentity(identity.id(), identity.name(),
								"mtls:" + identity.id() + ":" + newGeneration, fingerprint, identity.fingerprint(),
								newGeneration, identity.joinMethod(), identity.status(), notBefore, notAfter,
								identity.statusReason(), identity.statusChangedBy(), identity.statusChangedAt(),
								identity.version(), identity.createdAt(), identity.updatedAt());
						return gatewayIdentities.save(renewed)
								.onErrorMap(OptimisticLockingFailureException.class, race -> generationMismatch())
								.then(audit.record(identity.name(), identity.name(), "gateway.renew", "success", null,
										null,
										Map.of("generation", Long.toString(newGeneration), "fingerprint", fingerprint)))
								.thenReturn(GatewayEnrollmentService.toIssued(leaf, backend, identity.id(),
										newGeneration, notBefore, notAfter));
					});
		});
	}

	private static boolean fingerprintPins(GatewayIdentity identity, String presented) {
		return presented != null
				&& (presented.equals(identity.fingerprint()) || presented.equals(identity.prevFingerprint()));
	}

	// M4: audit the fail-closed denial (generic to the client, specific reason
	// server-side only).
	private Mono<IssuedIdentity> denied(GatewayIdentity identity, String reason) {
		return audit
				.record(identity.name(), identity.name(), "gateway.renew", "denied", null, null,
						Map.of("reason", reason))
				.then(Mono.error(new GatewayRequestException(GatewayRequestException.Reason.PERMISSION_DENIED,
						"renewal refused")));
	}

	private static GatewayRequestException unauthenticated() {
		return new GatewayRequestException(GatewayRequestException.Reason.UNAUTHENTICATED, "gateway identity unknown");
	}

	private static GatewayRequestException generationMismatch() {
		return new GatewayRequestException(GatewayRequestException.Reason.FAILED_PRECONDITION,
				"generation mismatch (renewal refused)");
	}
}
