package io.sessionlayer.controlplane.authz;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * FR-SESS-3 session-limit configuration
 * ({@code sessionlayer.session-limits.*}).
 *
 * <ul>
 * <li><b>default-max-concurrent</b> / <b>default-max-session-seconds</b> /
 * <b>default-idle-timeout-seconds</b> — the cluster-default session-limit knobs
 * as OPT-IN deployment-config values. Unset ⇒ unlimited/none (the stored
 * {@code operator_settings.default_*} column is left untouched, so existing
 * deployments are unaffected); set ⇒ reconciled into that column at bootstrap
 * and authoritative on each boot. Per-identity overrides live in
 * {@code config.session_limit_policy}.</li>
 * <li><b>lease-extension</b> — the SERVER-authoritative window
 * {@code ExtendSessionLease} re-stamps a live lease's {@code expires_at} to
 * (S25 exact accounting: a RunToTtl session outliving grant_expiry keeps its
 * slot while the Gateway re-extends ahead of expiry; the request carries no
 * duration, so a client can never park a lease in the far future). Default
 * 15m.</li>
 * <li><b>reaper.grace</b> — how far past a lease's {@code expires_at} the
 * leaked- lease sweep waits before releasing it (belt, so a just-expiring
 * still-active lease is never touched; default 5m).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.session-limits")
public class SessionLimitProperties {

	private Integer defaultMaxConcurrent;

	private Integer defaultMaxSessionSeconds;

	private Integer defaultIdleTimeoutSeconds;

	private Duration leaseExtension = Duration.ofMinutes(15);

	private final Reaper reaper = new Reaper();

	public Integer getDefaultMaxConcurrent() {
		return defaultMaxConcurrent;
	}

	public void setDefaultMaxConcurrent(Integer defaultMaxConcurrent) {
		this.defaultMaxConcurrent = defaultMaxConcurrent;
	}

	public Integer getDefaultMaxSessionSeconds() {
		return defaultMaxSessionSeconds;
	}

	public void setDefaultMaxSessionSeconds(Integer defaultMaxSessionSeconds) {
		this.defaultMaxSessionSeconds = defaultMaxSessionSeconds;
	}

	public Integer getDefaultIdleTimeoutSeconds() {
		return defaultIdleTimeoutSeconds;
	}

	public void setDefaultIdleTimeoutSeconds(Integer defaultIdleTimeoutSeconds) {
		this.defaultIdleTimeoutSeconds = defaultIdleTimeoutSeconds;
	}

	public Duration getLeaseExtension() {
		return leaseExtension;
	}

	public void setLeaseExtension(Duration leaseExtension) {
		this.leaseExtension = leaseExtension;
	}

	public Reaper getReaper() {
		return reaper;
	}

	public static class Reaper {

		private Duration grace = Duration.ofMinutes(5);

		public Duration getGrace() {
			return grace;
		}

		public void setGrace(Duration grace) {
			this.grace = grace;
		}
	}
}
