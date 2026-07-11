package io.sessionlayer.controlplane.auth;

import java.time.Instant;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Single-use guard for OAuth {@code private_key_jwt} client-assertion
 * {@code jti} values (FR-AUTH-12 / RFC 7523 §3): an assertion's {@code jti}
 * MUST NOT replay within its lifetime. Stores only the hash of the jti with the
 * assertion's own expiry; the atomic {@code INSERT ... ON CONFLICT DO NOTHING}
 * makes the first use win and any replay lose. Fail-closed: a store error is
 * treated as a replay (deny).
 */
@Service
public class ConsumedAssertionStore {

	private static final String INSERT = """
			INSERT INTO runtime.consumed_assertion (jti_hash, subject, not_after)
			VALUES (:jtiHash, :subject, :notAfter)
			ON CONFLICT (jti_hash) DO NOTHING""";

	private final DatabaseClient db;

	public ConsumedAssertionStore(DatabaseClient db) {
		this.db = db;
	}

	/** True if this jti is being consumed for the first time; false on replay. */
	public Mono<Boolean> consumeOnce(String jtiHash, String subject, Instant notAfter) {
		return db.sql(INSERT).bind("jtiHash", jtiHash).bind("subject", subject).bind("notAfter", notAfter).fetch()
				.rowsUpdated().map(n -> n == 1L).onErrorReturn(false);
	}
}
