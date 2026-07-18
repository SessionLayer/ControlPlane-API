package io.sessionlayer.controlplane.authz;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * FR-SESS-3 session-limit configuration
 * ({@code sessionlayer.session-limits.*}).
 *
 * <ul>
 * <li><b>default-max-concurrent</b> — the cluster-default concurrent-session
 * cap as an OPT-IN deployment-config knob. Unset ⇒ unlimited (the stored
 * {@code operator_settings.default_max_concurrent_sessions} is left untouched,
 * so existing deployments are unaffected); set ⇒ reconciled into that column at
 * bootstrap and authoritative on each boot. Per-identity overrides live in
 * {@code config.session_limit_policy}.</li>
 * <li><b>reaper.grace</b> — how far past a lease's {@code expires_at} the
 * leaked- lease sweep waits before releasing it (belt, so a just-expiring
 * still-active lease is never touched; default 5m).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.session-limits")
public class SessionLimitProperties {

	private Integer defaultMaxConcurrent;

	private final Reaper reaper = new Reaper();

	public Integer getDefaultMaxConcurrent() {
		return defaultMaxConcurrent;
	}

	public void setDefaultMaxConcurrent(Integer defaultMaxConcurrent) {
		this.defaultMaxConcurrent = defaultMaxConcurrent;
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
