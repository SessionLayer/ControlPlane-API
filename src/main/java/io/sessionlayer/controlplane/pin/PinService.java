package io.sessionlayer.controlplane.pin;

import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.authz.AuthzProperties;
import io.sessionlayer.controlplane.data.runtime.Pin;
import io.sessionlayer.controlplane.data.runtime.PinRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Pin store (Design §5.5, FR-AUTH-10/11). A pin is an authentication shortcut:
 * {@code {fingerprint, identity, source-cidr, principals, expires_at}}. The TTL
 * is <b>capped at the authorization TTL</b>
 * ({@code sessionlayer.authz.max-grant-ttl}). Source-IP is a deny-only reducer
 * stored here and enforced at reconnect by the Gateway (S7). Pins are revocable
 * by an admin, on offboarding, on lock, and on OIDC back-channel logout
 * (FR-AUTH-11). Every mutation is audited.
 */
@Service
public class PinService {

	private final PinRepository pins;
	private final AuthzProperties authzProperties;
	private final AuditWriter audit;

	public PinService(PinRepository pins, AuthzProperties authzProperties, AuditWriter audit) {
		this.pins = pins;
		this.authzProperties = authzProperties;
		this.audit = audit;
	}

	/**
	 * Create or re-issue the pin for {@code (fingerprint, identity)} (TTL capped).
	 */
	public Mono<Pin> create(String fingerprint, String identity, String sourceCidr, List<String> principals,
			long ttlSeconds, String actor) {
		if (fingerprint == null || fingerprint.isBlank() || identity == null || identity.isBlank() || principals == null
				|| principals.isEmpty()) {
			return Mono.error(new IllegalArgumentException("fingerprint, identity and principals are required"));
		}
		long cappedSeconds = Math.min(Math.max(1, ttlSeconds), authzProperties.getMaxGrantTtl().getSeconds());
		Instant expiresAt = Instant.now().plus(Duration.ofSeconds(cappedSeconds));
		return pins.findByFingerprintAndIdentity(fingerprint, identity)
				.map(existing -> existing.reissued(sourceCidr, principals, expiresAt))
				.defaultIfEmpty(Pin.create(fingerprint, identity, sourceCidr, principals, expiresAt))
				.flatMap(
						pins::save)
				.flatMap(saved -> audit.record(actor, identity, "pin.create", "success", null, null,
						Map.of("pin_id", saved.id().toString(), "fingerprint", fingerprint, "ttl_seconds",
								String.valueOf(cappedSeconds)))
						.thenReturn(saved));
	}

	/** Active (unrevoked, unexpired) pins for an identity. */
	public Flux<Pin> listActive(String identity) {
		Instant now = Instant.now();
		return pins.findByIdentity(identity).filter(p -> p.active(now));
	}

	/** Revoke a single pin (idempotent). Empty if the pin does not exist. */
	public Mono<Pin> revoke(UUID pinId, String actor, String reason) {
		return pins.findById(pinId).flatMap(pin -> {
			if (pin.revokedAt() != null) {
				return Mono.just(pin);
			}
			return pins.save(pin.revoked(Instant.now()))
					.flatMap(saved -> audit.record(actor, pin.identity(), "pin.revoke", "success", null, null,
							Map.of("pin_id", pinId.toString(), "reason", reason)).thenReturn(saved));
		});
	}

	/**
	 * Revoke every active pin for an identity (offboarding / lock / back-channel
	 * logout).
	 */
	public Mono<Long> revokeForIdentity(String identity, String actor, String reason) {
		Instant now = Instant.now();
		return pins.findByIdentity(identity).filter(p -> p.revokedAt() == null).flatMap(p -> pins.save(p.revoked(now)))
				.count().flatMap(
						count -> audit
								.record(actor, identity, "pin.revoke", "success", null, null,
										Map.of("reason", reason, "revoked_count", String.valueOf(count)))
								.thenReturn(count));
	}
}
