package io.sessionlayer.controlplane.authz;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Open values for the Session Ten lock-push feed
 * ({@code sessionlayer.locks.*}), with documented defaults (RESULT §9):
 *
 * <ul>
 * <li><b>heartbeat-interval</b> — the liveness beat on the {@code StreamLocks}
 * stream (default 10s). The Gateway marks the stream unhealthy past its own
 * threshold (a few missed beats) and forces per-channel re-validate
 * ({@code decision_ttl → 0}).</li>
 * <li><b>stream-buffer-capacity</b> — the per-connection bounded buffer of
 * pending events (default 512). On overflow (a stalled Gateway) the stream is
 * failed so the Gateway reconnects and RESYNCs — never a silently-dropped
 * deny.</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "sessionlayer.locks")
public class LockFeedProperties {

	private Duration heartbeatInterval = Duration.ofSeconds(10);

	private int streamBufferCapacity = 512;

	public Duration getHeartbeatInterval() {
		return heartbeatInterval;
	}

	public void setHeartbeatInterval(Duration heartbeatInterval) {
		this.heartbeatInterval = heartbeatInterval;
	}

	public int getStreamBufferCapacity() {
		return streamBufferCapacity;
	}

	public void setStreamBufferCapacity(int streamBufferCapacity) {
		this.streamBufferCapacity = streamBufferCapacity;
	}
}
