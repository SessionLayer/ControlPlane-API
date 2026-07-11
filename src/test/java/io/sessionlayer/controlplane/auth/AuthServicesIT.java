package io.sessionlayer.controlplane.auth;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.OtpRepository;
import io.sessionlayer.controlplane.data.runtime.PinRepository;
import io.sessionlayer.controlplane.otp.OtpService;
import io.sessionlayer.controlplane.pin.PinService;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;

/**
 * OTP (FR-AUTH-9), pins (FR-AUTH-10/11), rate limiter + assertion replay guard.
 */
class AuthServicesIT extends AbstractAuthIT {

	@Autowired
	OtpService otpService;
	@Autowired
	OtpRepository otps;
	@Autowired
	PinService pinService;
	@Autowired
	PinRepository pins;
	@Autowired
	RateLimiter rateLimiter;
	@Autowired
	ConsumedAssertionStore consumedAssertions;
	@Autowired
	DatabaseClient db;

	@Test
	void otpIsSingleUseAndStoredHashedAndSourceBound() {
		OtpService.IssuedOtp issued = otpService.issue("alice", List.of("deploy"), "10.0.0.0/24", 120, "admin").block();
		assertThat(issued).isNotNull();
		// Stored hashed, never raw.
		String stored = db.sql("SELECT otp_hash FROM runtime.otp WHERE id=:id").bind("id", issued.id())
				.map(r -> r.get(0, String.class)).one().block();
		assertThat(stored).isNotEqualTo(issued.otp()).isEqualTo(Secrets.sha256Hex(issued.otp()));

		// First validate from an in-CIDR source succeeds and resolves the record
		// identity.
		StepVerifier.create(otpService.validate(issued.otp(), "10.0.0.5")).assertNext(resolved -> {
			assertThat(resolved.identity()).isEqualTo("alice");
			assertThat(resolved.principals()).containsExactly("deploy");
		}).verifyComplete();
		// Replay is rejected (single-use).
		StepVerifier.create(otpService.validate(issued.otp(), "10.0.0.5")).verifyComplete(); // empty
	}

	@Test
	void otpFromWrongSourceIsRejectedWithoutBurningIt() {
		OtpService.IssuedOtp issued = otpService.issue("bob", List.of("dba"), "10.0.0.0/24", 120, "admin").block();
		StepVerifier.create(otpService.validate(issued.otp(), "192.168.1.9")).verifyComplete(); // empty
		// The OTP is NOT consumed (wrong source matched no row), so the legit source
		// works.
		assertThat(otps.findById(issued.id()).block().used()).isFalse();
		StepVerifier.create(otpService.validate(issued.otp(), "10.0.0.1"))
				.assertNext(r -> assertThat(r.identity()).isEqualTo("bob")).verifyComplete();
	}

	@Test
	void otpSourceCidrWithHostBitsDoesNotThrow() {
		// Operator-friendly host-bits CIDR (stored via lenient ::inet). The validate
		// query must use ::inet (not strict ::cidr) so this matches instead of
		// erroring.
		OtpService.IssuedOtp issued = otpService.issue("frank", List.of("deploy"), "192.168.1.5/24", 120, "admin")
				.block();
		StepVerifier.create(otpService.validate(issued.otp(), "192.168.1.9"))
				.assertNext(r -> assertThat(r.identity()).isEqualTo("frank")).verifyComplete();
	}

	@Test
	void malformedSourceIpFailsClosed() {
		OtpService.IssuedOtp issued = otpService.issue("grace", List.of("deploy"), "10.0.0.0/24", 120, "admin").block();
		// A malformed source IP must deny (not 500) and must not consume the OTP.
		StepVerifier.create(otpService.validate(issued.otp(), "not-an-ip")).verifyComplete();
		assertThat(otps.findById(issued.id()).block().used()).isFalse();
	}

	@Test
	void expiredOtpIsRejected() {
		OtpService.IssuedOtp issued = otpService.issue("carol", List.of("deploy"), null, 120, "admin").block();
		db.sql("UPDATE runtime.otp SET expires_at = now() - interval '1 minute' WHERE id=:id").bind("id", issued.id())
				.fetch().rowsUpdated().block();
		StepVerifier.create(otpService.validate(issued.otp(), "10.0.0.1")).verifyComplete(); // empty
	}

	@Test
	void rateLimiterTripsAtTheConfiguredMax() {
		String bucket = "test:" + UUID.randomUUID();
		Duration window = Duration.ofMinutes(5);
		assertThat(rateLimiter.tryAcquire(bucket, 2, window).block()).isTrue();
		assertThat(rateLimiter.tryAcquire(bucket, 2, window).block()).isTrue();
		assertThat(rateLimiter.tryAcquire(bucket, 2, window).block()).isFalse();
	}

	@Test
	void assertionJtiIsSingleUse() {
		String jtiHash = Secrets.sha256Hex("jti-" + UUID.randomUUID());
		Instant exp = Instant.now().plusSeconds(60);
		assertThat(consumedAssertions.consumeOnce(jtiHash, "svc-1", exp).block()).isTrue();
		assertThat(consumedAssertions.consumeOnce(jtiHash, "svc-1", exp).block()).isFalse();
	}

	@Test
	void pinTtlIsCappedAndRevocable() {
		// A huge requested TTL is capped at the authorization TTL (default 1h).
		var pin = pinService.create("SHA256:aaa", "dave", "10.0.0.0/24", List.of("deploy"), 999_999L, "admin").block();
		assertThat(pin.expiresAt()).isBefore(Instant.now().plus(Duration.ofHours(1)).plusSeconds(5));
		assertThat(pinService.listActive("dave").collectList().block()).hasSize(1);

		// Re-pin updates in place (unique fingerprint+identity).
		pinService.create("SHA256:aaa", "dave", "10.0.0.0/24", List.of("deploy", "dba"), 600L, "admin").block();
		assertThat(pins.findByIdentity("dave").collectList().block()).hasSize(1);

		// Admin revoke.
		pinService.revoke(pin.id(), "admin", "test").block();
		assertThat(pinService.listActive("dave").collectList().block()).isEmpty();
	}

	@Test
	void revokeForIdentityRevokesAllActivePins() {
		pinService.create("SHA256:b1", "erin", null, List.of("deploy"), 600L, "admin").block();
		pinService.create("SHA256:b2", "erin", null, List.of("dba"), 600L, "admin").block();
		Long revoked = pinService.revokeForIdentity("erin", "idp", "backchannel_logout").block();
		assertThat(revoked).isEqualTo(2L);
		assertThat(pinService.listActive("erin").collectList().block()).isEmpty();
	}
}
