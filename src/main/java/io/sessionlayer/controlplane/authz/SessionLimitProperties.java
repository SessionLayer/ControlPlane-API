package io.sessionlayer.controlplane.authz;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * FR-SESS-3 cluster-default concurrent-session cap as an OPT-IN
 * deployment-config knob
 * ({@code sessionlayer.session-limits.default-max-concurrent}). Unset ⇒
 * unlimited (the stored
 * {@code operator_settings.default_max_concurrent_sessions} is left untouched,
 * so existing deployments are unaffected); set ⇒ reconciled into that column at
 * bootstrap and authoritative on each boot. Per-identity overrides live in
 * {@code config.session_limit_policy}.
 */
@ConfigurationProperties(prefix = "sessionlayer.session-limits")
public class SessionLimitProperties {

	private Integer defaultMaxConcurrent;

	public Integer getDefaultMaxConcurrent() {
		return defaultMaxConcurrent;
	}

	public void setDefaultMaxConcurrent(Integer defaultMaxConcurrent) {
		this.defaultMaxConcurrent = defaultMaxConcurrent;
	}
}
