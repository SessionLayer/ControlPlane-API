package io.sessionlayer.controlplane.authz;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Open values for the Session Five authorization layer
 * ({@code sessionlayer.authz.*}), with documented defaults (RESULT §6):
 *
 * <ul>
 * <li><b>decision-ttl</b> — how long the Gateway may serve per-channel checks
 * from a cached decision context before re-authorizing (~30-60s; default
 * 45s).</li>
 * <li><b>max-grant-ttl</b> — the ceiling applied to a grant's TTL when
 * computing {@code grant_expiry = min(standing/JIT TTL, access-cred TTL)}.
 * Until S6 feeds the real upstream auth-credential expiry, this ceiling stands
 * in for the access-cred TTL (default 1h).</li>
 * <li><b>context-signer-cert-ttl</b> — validity of the decision-context signer
 * leaf, re-minted from the internal mTLS CA at startup (default 24h; the
 * Gateway pins the CA, not the leaf).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.authz")
public class AuthzProperties {

	private Duration decisionTtl = Duration.ofSeconds(45);

	private Duration maxGrantTtl = Duration.ofHours(1);

	private Duration contextSignerCertTtl = Duration.ofHours(24);

	public Duration getDecisionTtl() {
		return decisionTtl;
	}

	public void setDecisionTtl(Duration decisionTtl) {
		this.decisionTtl = decisionTtl;
	}

	public Duration getMaxGrantTtl() {
		return maxGrantTtl;
	}

	public void setMaxGrantTtl(Duration maxGrantTtl) {
		this.maxGrantTtl = maxGrantTtl;
	}

	public Duration getContextSignerCertTtl() {
		return contextSignerCertTtl;
	}

	public void setContextSignerCertTtl(Duration contextSignerCertTtl) {
		this.contextSignerCertTtl = contextSignerCertTtl;
	}
}
