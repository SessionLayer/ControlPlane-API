package io.sessionlayer.controlplane.auth;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Tunables for the authentication surface (Open values, RESULT §7): OTP entropy
 * and the fixed-window rate limits on the OTP-verify and token endpoints
 * (FR-AUTH-9). OTP TTL comes from {@code operator_settings.otp_ttl_seconds}
 * (60–300s); the pin TTL cap comes from
 * {@code sessionlayer.authz.max-grant-ttl}.
 */
@ConfigurationProperties(prefix = "sessionlayer.auth")
public class AuthProperties {

	/** OTP entropy in bytes (≥16 = ≥128 bits, FR-AUTH-9). */
	private int otpEntropyBytes = 16;

	private final RateLimit otpVerify = new RateLimit(5, Duration.ofMinutes(1));
	private final RateLimit tokenEndpoint = new RateLimit(30, Duration.ofMinutes(1));
	private final RateLimit devicePoll = new RateLimit(60, Duration.ofMinutes(1));

	public int getOtpEntropyBytes() {
		return otpEntropyBytes;
	}

	public void setOtpEntropyBytes(int otpEntropyBytes) {
		this.otpEntropyBytes = otpEntropyBytes;
	}

	public RateLimit getOtpVerify() {
		return otpVerify;
	}

	public RateLimit getTokenEndpoint() {
		return tokenEndpoint;
	}

	public RateLimit getDevicePoll() {
		return devicePoll;
	}

	/** A fixed-window rate limit: at most {@code max} events per {@code window}. */
	public static class RateLimit {
		private int max;
		private Duration window;

		public RateLimit() {
		}

		RateLimit(int max, Duration window) {
			this.max = max;
			this.window = window;
		}

		public int getMax() {
			return max;
		}

		public void setMax(int max) {
			this.max = max;
		}

		public Duration getWindow() {
			return window;
		}

		public void setWindow(Duration window) {
			this.window = window;
		}
	}
}
