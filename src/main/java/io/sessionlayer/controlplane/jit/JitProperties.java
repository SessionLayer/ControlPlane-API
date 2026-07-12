package io.sessionlayer.controlplane.jit;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Open values for the JIT access model ({@code sessionlayer.jit.*}), with
 * documented defaults (RESULT §7):
 *
 * <ul>
 * <li><b>approval-window</b> — how long a request may sit REQUESTED/
 * PENDING_APPROVAL before it EXPIRES unapproved (the approval clock; default
 * 30m).</li>
 * <li><b>max-grant-ttl</b> — the cluster ceiling on a JIT grant's TTL; the
 * effective grant TTL is {@code min(jit_policy.max_ttl_seconds, ceiling)} and
 * the grant clock starts at final approval (default 8h).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.jit")
public class JitProperties {

	private Duration approvalWindow = Duration.ofMinutes(30);

	private Duration maxGrantTtl = Duration.ofHours(8);

	public Duration getApprovalWindow() {
		return approvalWindow;
	}

	public void setApprovalWindow(Duration approvalWindow) {
		this.approvalWindow = approvalWindow;
	}

	public Duration getMaxGrantTtl() {
		return maxGrantTtl;
	}

	public void setMaxGrantTtl(Duration maxGrantTtl) {
		this.maxGrantTtl = maxGrantTtl;
	}
}
