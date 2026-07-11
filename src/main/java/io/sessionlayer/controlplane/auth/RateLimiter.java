package io.sessionlayer.controlplane.auth;

import io.sessionlayer.controlplane.auth.AuthProperties.RateLimit;
import java.time.Duration;
import java.time.Instant;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * A durable fixed-window rate limiter (FR-AUTH-9) backed by
 * {@code runtime.auth_rate_limit}. Unlike an in-memory limiter it holds across
 * HA instances and restarts. Each call increments the current window's counter
 * with one atomic upsert; a request whose resulting count exceeds {@code max}
 * is denied. Fail-closed: a limiter error denies (never silently allows an
 * unbounded auth endpoint).
 */
@Service
public class RateLimiter {

	private static final String UPSERT = """
			INSERT INTO runtime.auth_rate_limit (bucket, window_start, count, updated_at)
			VALUES (:bucket, :windowStart, 1, now())
			ON CONFLICT (bucket) DO UPDATE SET
			  count = CASE WHEN runtime.auth_rate_limit.window_start = :windowStart
			               THEN runtime.auth_rate_limit.count + 1 ELSE 1 END,
			  window_start = :windowStart,
			  updated_at = now()
			RETURNING count""";

	private final DatabaseClient db;

	public RateLimiter(DatabaseClient db) {
		this.db = db;
	}

	/** True if the event is within the limit; false if it should be throttled. */
	public Mono<Boolean> tryAcquire(String bucket, RateLimit limit) {
		return tryAcquire(bucket, limit.getMax(), limit.getWindow());
	}

	public Mono<Boolean> tryAcquire(String bucket, int max, Duration window) {
		long windowMillis = Math.max(1, window.toMillis());
		Instant windowStart = Instant.ofEpochMilli((System.currentTimeMillis() / windowMillis) * windowMillis);
		return db.sql(UPSERT).bind("bucket", bucket).bind("windowStart", windowStart).map(row -> row.get(0, Long.class))
				.one().map(count -> count != null && count <= max).onErrorReturn(false);
	}
}
