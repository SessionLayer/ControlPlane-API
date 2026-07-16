package io.sessionlayer.controlplane.configapi;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed config for runtime session management ({@code sessionlayer.session.*}).
 * {@code terminateLockTtl} bounds the identity-scoped Lock an operator
 * terminate pushes: long enough that a Gateway briefly disconnected still tears
 * the session down on its next resync snapshot, short enough that the identity
 * can reconnect afterwards under unchanged policy.
 */
@ConfigurationProperties(prefix = "sessionlayer.session")
public class SessionManagementProperties {

	private Duration terminateLockTtl = Duration.ofMinutes(5);

	public Duration getTerminateLockTtl() {
		return terminateLockTtl;
	}

	public void setTerminateLockTtl(Duration terminateLockTtl) {
		this.terminateLockTtl = terminateLockTtl;
	}
}
