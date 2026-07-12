package io.sessionlayer.controlplane.breakglass;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Open values for the break-glass access model
 * ({@code sessionlayer.breakglass.*}), with documented defaults (RESULT §7):
 *
 * <ul>
 * <li><b>grant-ttl</b> — the break-glass grant TTL; the effective grant expiry
 * is {@code min(grant-ttl, access-cred ceiling)} (emergency access is short;
 * default 1h).</li>
 * <li><b>token-ttl</b> — how long the single-use break-glass token minted at
 * RESOLVE is valid for the follow-up Authorize (default 2m).</li>
 * <li><b>offline-code-count</b> / <b>offline-code-ttl</b> /
 * <b>offline-code-entropy-bytes</b> — batch issuance defaults (10 codes, 90d,
 * ≥128-bit each).</li>
 * <li><b>review-sla</b> — advisory deadline for the mandatory post-hoc review
 * of an activation (default 72h; an unreviewed activation is a standing signal,
 * not an auto-clear).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.breakglass")
public class BreakglassProperties {

	private Duration grantTtl = Duration.ofHours(1);

	private Duration tokenTtl = Duration.ofMinutes(2);

	private int offlineCodeCount = 10;

	private Duration offlineCodeTtl = Duration.ofDays(90);

	private int offlineCodeEntropyBytes = 16; // 128-bit

	private Duration reviewSla = Duration.ofHours(72);

	public Duration getGrantTtl() {
		return grantTtl;
	}

	public void setGrantTtl(Duration grantTtl) {
		this.grantTtl = grantTtl;
	}

	public Duration getTokenTtl() {
		return tokenTtl;
	}

	public void setTokenTtl(Duration tokenTtl) {
		this.tokenTtl = tokenTtl;
	}

	public int getOfflineCodeCount() {
		return offlineCodeCount;
	}

	public void setOfflineCodeCount(int offlineCodeCount) {
		this.offlineCodeCount = offlineCodeCount;
	}

	public Duration getOfflineCodeTtl() {
		return offlineCodeTtl;
	}

	public void setOfflineCodeTtl(Duration offlineCodeTtl) {
		this.offlineCodeTtl = offlineCodeTtl;
	}

	public int getOfflineCodeEntropyBytes() {
		return offlineCodeEntropyBytes;
	}

	public void setOfflineCodeEntropyBytes(int offlineCodeEntropyBytes) {
		this.offlineCodeEntropyBytes = offlineCodeEntropyBytes;
	}

	public Duration getReviewSla() {
		return reviewSla;
	}

	public void setReviewSla(Duration reviewSla) {
		this.reviewSla = reviewSla;
	}
}
