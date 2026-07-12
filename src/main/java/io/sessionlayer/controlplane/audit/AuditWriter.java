package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Thin append-only writer for the correlated audit stream
 * ({@code runtime.audit_event}, Design §12.2). The mTLS identity + signing +
 * recording paths emit through this so an enroll/renew/sign/record is a
 * first-class audit record. INSERT only — the table is append-only (a DB
 * trigger rejects UPDATE/DELETE), so this never mutates an existing row. No key
 * material is ever recorded (only fingerprints/ids).
 *
 * <p>
 * Every write links into the S9 tamper-evidence <b>hash chain</b> (FR-AUD-3):
 * {@code record_hash = SHA-256(prev_hash ‖ canonical(event))} where
 * {@code prev_hash} is the previous row's {@code record_hash} in {@code seq}
 * order (see {@link AuditRecordHash}). Because R2DBC inserts are concurrent
 * (and HA runs multiple CP writers), the chain is serialized per insert with a
 * transaction-scoped Postgres advisory lock: within one transaction take the
 * lock, read the current chain head, compute this row's hash, and insert (which
 * assigns the next {@code seq}). Audit writes are not ultra-hot and Design §14
 * already treats audit as synchronously replicated, so the serialization cost
 * is acceptable for a single, well-defined predecessor and gap/fork detection.
 */
@Service
public class AuditWriter {

	/** Transaction-scoped advisory-lock key serializing the chain ("SL_AUD_C"). */
	private static final long CHAIN_LOCK = 0x53_4C_5F_41_55_44_5F_43L;

	private static final String LATEST_HASH = "SELECT record_hash FROM runtime.audit_event "
			+ "WHERE record_hash IS NOT NULL ORDER BY seq DESC LIMIT 1";

	private final AuditEventRepository events;
	private final ObjectMapper objectMapper;
	private final DatabaseClient db;
	private final TransactionalOperator tx;

	public AuditWriter(AuditEventRepository events, ObjectMapper objectMapper, DatabaseClient db,
			TransactionalOperator tx) {
		this.events = events;
		this.objectMapper = objectMapper;
		this.db = db;
		this.tx = tx;
	}

	/**
	 * Record one audit event. {@code detail} is a small, secret-free string map
	 * stored as jsonb; {@code sessionId}/{@code nodeId} may be null.
	 */
	public Mono<Void> record(String actor, String subject, String action, String outcome, UUID sessionId, UUID nodeId,
			Map<String, String> detail) {
		ObjectNode detailNode = objectMapper.createObjectNode();
		if (detail != null) {
			detail.forEach((k, v) -> detailNode.put(k, v));
		}
		// Truncate to microseconds so the value hashed equals the value that
		// round-trips from the timestamptz column (the chain must recompute exactly).
		Instant occurredAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
		AuditEvent event = AuditEvent.create(occurredAt, actor, subject, action, outcome, null, sessionId, nodeId, null,
				null, null, null, detailNode);
		Mono<Void> chainedInsert = db.sql("SELECT pg_advisory_xact_lock(:k)").bind("k", CHAIN_LOCK).fetch()
				.rowsUpdated()
				.then(db.sql(LATEST_HASH).map((row, meta) -> row.get("record_hash", String.class)).first()
						.defaultIfEmpty(AuditRecordHash.GENESIS))
				.flatMap(
						prevHash -> events.save(event.withChain(prevHash, AuditRecordHash.recordHash(prevHash, event))))
				.then();
		return tx.transactional(chainedInsert);
	}
}
