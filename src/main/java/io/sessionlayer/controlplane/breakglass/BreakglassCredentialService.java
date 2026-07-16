package io.sessionlayer.controlplane.breakglass;

import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.data.runtime.BreakglassCredential;
import io.sessionlayer.controlplane.data.runtime.BreakglassCredentialRepository;
import io.sessionlayer.controlplane.data.runtime.BreakglassOfflineCode;
import io.sessionlayer.controlplane.data.runtime.BreakglassOfflineCodeRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;

/**
 * Manages the break-glass credential set (FR-ACC-6, {@code breakglass:manage}):
 * registers FIDO2 {@code sk-ecdsa} PUBLIC keys (primary) and issues batches of
 * pre-shared single-use offline codes (fallback). Attestation is not required —
 * an admin self-registers the public key — so the trust model is "an admin
 * vouched for this key"; only PUBLIC key material and code HASHES are ever
 * stored. Raw offline codes are returned exactly once at issuance. Every
 * mutation is audited (FR-API-5).
 */
@Service
public class BreakglassCredentialService {

	private final BreakglassCredentialRepository credentials;
	private final BreakglassOfflineCodeRepository codes;
	private final BreakglassProperties properties;
	private final AuditEventStore audit;

	public BreakglassCredentialService(BreakglassCredentialRepository credentials,
			BreakglassOfflineCodeRepository codes, BreakglassProperties properties, AuditEventStore audit) {
		this.credentials = credentials;
		this.codes = codes;
		this.properties = properties;
		this.audit = audit;
	}

	/**
	 * A validation failure surfaced as an RFC-9457 400 by the controller's handler.
	 */
	public static final class InvalidBreakglassException extends RuntimeException {
		public InvalidBreakglassException(String message) {
			super(message);
		}
	}

	/** A batch of raw offline codes returned once, with their stored ids. */
	public record IssuedCodes(List<UUID> ids, List<String> rawCodes, Instant expiresAt) {
	}

	public Mono<BreakglassCredential> register(byte[] skBlob, String identity, List<String> allowedPrincipals,
			JsonNode nodeSelector, Instant expiresAt, String actor) {
		if (identity == null || identity.isBlank()) {
			return Mono.error(new InvalidBreakglassException("identity is required"));
		}
		if (allowedPrincipals == null || allowedPrincipals.isEmpty()) {
			return Mono.error(new InvalidBreakglassException("at least one allowed principal is required"));
		}
		SkEcdsaPublicKey.Parsed parsed;
		try {
			parsed = SkEcdsaPublicKey.parse(skBlob);
		} catch (RuntimeException malformed) {
			return Mono.error(new InvalidBreakglassException("not a valid sk-ecdsa-sha2-nistp256 public key"));
		}
		BreakglassCredential credential = BreakglassCredential.register(parsed.fingerprint(), skBlob,
				parsed.application(), identity, List.copyOf(allowedPrincipals), nodeSelector, expiresAt, actor);
		return credentials.save(credential)
				.flatMap(saved -> audit
						.record(actor, identity, "breakglass.credential.register", "success", null, null,
								Map.of("credential_id", saved.id().toString(), "fingerprint", saved.keyFingerprint()))
						.thenReturn(saved));
	}

	public Mono<Boolean> revoke(UUID credentialId, String actor) {
		Instant now = Instant.now();
		return credentials.findById(credentialId)
				.flatMap(cred -> credentials.save(cred.revoked(now))
						.then(audit.record(actor, cred.identity(), "breakglass.credential.revoke", "success", null,
								null, Map.of("credential_id", credentialId.toString())))
						.thenReturn(true))
				.defaultIfEmpty(false);
	}

	public Flux<BreakglassCredential> list() {
		return credentials.findAll();
	}

	public Mono<IssuedCodes> issueOfflineCodes(String identity, List<String> allowedPrincipals, JsonNode nodeSelector,
			String sourceCidr, Integer count, Integer ttlSeconds, String actor) {
		if (identity == null || identity.isBlank()) {
			return Mono.error(new InvalidBreakglassException("identity is required"));
		}
		if (allowedPrincipals == null || allowedPrincipals.isEmpty()) {
			return Mono.error(new InvalidBreakglassException("at least one allowed principal is required"));
		}
		int n = clamp(count == null ? properties.getOfflineCodeCount() : count, 1, 100);
		Duration ttl = ttlSeconds == null ? properties.getOfflineCodeTtl() : Duration.ofSeconds(ttlSeconds);
		Instant expiresAt = Instant.now().plus(ttl);
		List<String> raw = new ArrayList<>(n);
		List<BreakglassOfflineCode> rows = new ArrayList<>(n);
		for (int i = 0; i < n; i++) {
			String code = Secrets.randomBase32(properties.getOfflineCodeEntropyBytes());
			raw.add(code);
			rows.add(BreakglassOfflineCode.issue(Secrets.sha256Hex(code), identity, List.copyOf(allowedPrincipals),
					nodeSelector, sourceCidr, expiresAt, actor));
		}
		return codes.saveAll(rows).map(BreakglassOfflineCode::id).collectList()
				.flatMap(ids -> audit
						.record(actor, identity, "breakglass.offline_code.issue", "success", null, null,
								Map.of("count", Integer.toString(n), "identity", identity))
						.thenReturn(new IssuedCodes(ids, raw, expiresAt)));
	}

	public Flux<BreakglassOfflineCode> listOfflineCodes() {
		return codes.findAll();
	}

	private static int clamp(int value, int min, int max) {
		return Math.max(min, Math.min(max, value));
	}
}
