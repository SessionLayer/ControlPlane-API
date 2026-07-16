package io.sessionlayer.controlplane.web;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed config for the audit-event search time window
 * ({@code sessionlayer.audit.search.*} — a SESSION §8 open value). Bounds a
 * scan over the partitioned {@code audit_event} table so no query runs without
 * a lower time bound (Postgres cannot prune partitions otherwise): an
 * unfiltered search defaults to {@code defaultWindow} of recent history, and an
 * explicit range wider than {@code maxWindow} is rejected ({@code 422} — a
 * semantic bound on well-formed input). Defaults: 90-day default window,
 * 366-day maximum (generous — an auditor with an explicit range within the max
 * is never surprised).
 */
@ConfigurationProperties(prefix = "sessionlayer.audit.search")
public class AuditSearchProperties {

	private Duration defaultWindow = Duration.ofDays(90);
	private Duration maxWindow = Duration.ofDays(366);

	public Duration getDefaultWindow() {
		return defaultWindow;
	}

	public void setDefaultWindow(Duration defaultWindow) {
		this.defaultWindow = defaultWindow;
	}

	public Duration getMaxWindow() {
		return maxWindow;
	}

	public void setMaxWindow(Duration maxWindow) {
		this.maxWindow = maxWindow;
	}
}
