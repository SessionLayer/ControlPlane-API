package io.sessionlayer.controlplane.machine;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Machine-identity token configuration (Design §5.6, FR-AUTH-12). Machine
 * consumers exchange a client credential (private_key_jwt / mTLS preferred) for
 * a short-lived CP-signed bearer token; the CP is the issuer and validates its
 * own tokens on the resource-server path.
 */
@ConfigurationProperties(prefix = "sessionlayer.machine")
public class MachineTokenProperties {

	/** The {@code iss} the CP stamps into (and requires on) machine tokens. */
	private String issuer = "sessionlayer://cp";

	/** The {@code aud} the CP stamps into machine tokens (its own API). */
	private String audience = "sessionlayer-cp-api";

	/** Machine-token lifetime (short; Design §5.6). */
	private Duration tokenTtl = Duration.ofMinutes(5);

	/** Small skew for {@code exp} validation. */
	private Duration clockSkew = Duration.ofSeconds(30);

	/** Max age of a presented private_key_jwt client assertion (RFC 7523). */
	private Duration maxAssertionAge = Duration.ofMinutes(5);

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getAudience() {
		return audience;
	}

	public void setAudience(String audience) {
		this.audience = audience;
	}

	public Duration getTokenTtl() {
		return tokenTtl;
	}

	public void setTokenTtl(Duration tokenTtl) {
		this.tokenTtl = tokenTtl;
	}

	public Duration getClockSkew() {
		return clockSkew;
	}

	public void setClockSkew(Duration clockSkew) {
		this.clockSkew = clockSkew;
	}

	public Duration getMaxAssertionAge() {
		return maxAssertionAge;
	}

	public void setMaxAssertionAge(Duration maxAssertionAge) {
		this.maxAssertionAge = maxAssertionAge;
	}
}
