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
 * <li><b>revoke-lock-ttl</b> — the BOUNDED lifetime of the strict Lock a revoke
 * emits. The lock's only job is tearing down the LIVE session (the REVOKED
 * state already blocks re-auth), so it needs to live only long enough to
 * propagate to every Gateway, then auto-clear — never permanent (default
 * 120s).</li>
 * <li><b>lookup-timeout</b> — bounds {@code findUsableGrant} (S30: now called
 * UNCONDITIONALLY on every connect, standing-allowed or not). A degraded
 * {@code jit_request} table must never turn into a fleet-wide connect stall — a
 * timeout here degrades to "no usable grant" (§8.4: JIT only ever ADDS access,
 * so losing it narrows, never widens; the standing-only decision still
 * proceeds) rather than riding the pool's default statement timeout into a mass
 * fail-closed deny (default 150ms, well inside the NFR-4 250ms p95
 * establishment budget).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.jit")
public class JitProperties {

	private Duration approvalWindow = Duration.ofMinutes(30);

	private Duration maxGrantTtl = Duration.ofHours(8);

	private Duration revokeLockTtl = Duration.ofSeconds(120);

	private Duration lookupTimeout = Duration.ofMillis(150);

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

	public Duration getRevokeLockTtl() {
		return revokeLockTtl;
	}

	public void setRevokeLockTtl(Duration revokeLockTtl) {
		this.revokeLockTtl = revokeLockTtl;
	}

	public Duration getLookupTimeout() {
		return lookupTimeout;
	}

	public void setLookupTimeout(Duration lookupTimeout) {
		this.lookupTimeout = lookupTimeout;
	}
}
