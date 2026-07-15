package io.sessionlayer.controlplane.ha;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Open values for the Session Fifteen HA plane ({@code sessionlayer.ha.*}),
 * with documented defaults (RESULT §11):
 *
 * <ul>
 * <li><b>presence-staleness</b> — how long a presence owner's {@code last_seen}
 * may age before the owner is treated as dead (Design §10.2/§10.3). At the 10s
 * Gateway heartbeat interval this is three missed beats. It governs BOTH the
 * {@code Presence.Heartbeat} claim-vs-standby decision (a stale owner is taken
 * over) AND the {@code Authorize} routing gate (owner fields are populated only
 * when the owner is fresh; a stale owner reads as "node offline" and the
 * ingress Gateway fails closed).</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.ha")
public class HaProperties {

	private Duration presenceStaleness = Duration.ofSeconds(30);

	public Duration getPresenceStaleness() {
		return presenceStaleness;
	}

	public void setPresenceStaleness(Duration presenceStaleness) {
		this.presenceStaleness = presenceStaleness;
	}
}
