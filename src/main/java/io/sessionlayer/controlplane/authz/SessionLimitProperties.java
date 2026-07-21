package io.sessionlayer.controlplane.authz;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * still-active lease is never touched; default = the lease-extension
 * window).</li>
 * </ul>
 *
 * <p>
 * Reap-safety invariant (F5, held BY CONSTRUCTION via {@link #applyFloors()}):
 * a passed-expiry under-count is transient (the next successful extend
 * resurrects the counted window — {@code GREATEST} + the
 * {@code released_at IS NULL} guard); PERMANENT loss needs the reaper to stamp
 * {@code released_at} during a CP partition. That takes a partition longer than
 * {@code lease-extension/2 + reaper.grace} — with the grace floored to &ge; the
 * window, the Gateway's self-heal always wins any partition shorter than
 * {@code window + grace} (&gt; ~22.5m at defaults). The window is floored at
 * 60s: below ~10s it would collapse under the Gateway's 5s tick floor and the
 * count would flicker.
 */
@ConfigurationProperties(prefix = "sessionlayer.session-limits")
public class SessionLimitProperties {

	static final Duration MIN_LEASE_EXTENSION = Duration.ofSeconds(60);

	private static final Logger LOG = LoggerFactory.getLogger(SessionLimitProperties.class);

	private Integer defaultMaxConcurrent;

	private Integer defaultMaxSessionSeconds;

	private Integer defaultIdleTimeoutSeconds;

	private Duration leaseExtension = Duration.ofMinutes(15);

	private final Reaper reaper = new Reaper();

	// The F-1/F-2 startup floors: never fail boot, clamp + WARN so a bad operator
	// combo can't silently break the reap-safety invariant above.
	@PostConstruct
	void applyFloors() {
		if (leaseExtension == null || leaseExtension.compareTo(MIN_LEASE_EXTENSION) < 0) {
			LOG.warn(
					"sessionlayer.session-limits.lease-extension={} is below the {} floor — clamping (a tiny "
							+ "window collapses under the Gateway extend cadence and the concurrency count flickers)",
					leaseExtension, MIN_LEASE_EXTENSION);
			leaseExtension = MIN_LEASE_EXTENSION;
		}
		if (reaper.grace == null || reaper.grace.compareTo(leaseExtension) < 0) {
			if (reaper.grace != null) {
				LOG.warn("sessionlayer.session-limits.reaper.grace={} is below the lease-extension window {} — "
						+ "clamping to the window (reap-safety: the Gateway's extend self-heal must win any CP "
						+ "partition shorter than window + grace)", reaper.grace, leaseExtension);
			}
			reaper.grace = leaseExtension;
		}
	}

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

		// null = follow the lease-extension window (applyFloors resolves it), so
		// the default config boots WARN-free and the invariant holds untouched.
		private Duration grace;

		public Duration getGrace() {
			return grace;
		}

		public void setGrace(Duration grace) {
			this.grace = grace;
		}
	}
}
