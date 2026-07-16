package io.sessionlayer.controlplane.configapi;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed config for the {@code Idempotency-Key} replay store
 * ({@code sessionlayer.idempotency.*}, FR-API-1). {@code ttl} bounds how long a
 * recorded response is replayable; after it a reused key re-executes.
 */
@ConfigurationProperties(prefix = "sessionlayer.idempotency")
public class IdempotencyProperties {

	private Duration ttl = Duration.ofHours(24);

	public Duration getTtl() {
		return ttl;
	}

	public void setTtl(Duration ttl) {
		this.ttl = ttl;
	}
}
