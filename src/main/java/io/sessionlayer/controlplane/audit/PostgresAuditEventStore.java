package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.web.CursorPages;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.reactive.TransactionalOperator;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The Postgres implementation of {@link AuditEventStore} — the current backend
 * for the correlated audit stream ({@code runtime.audit_event}, Design §12.2).
 * INSERT + read only (the table is append-only; a DB trigger rejects
 * UPDATE/DELETE), so this never mutates an existing row. No key material is
 * ever recorded (only fingerprints/ids). Swappable behind the interface for a
 * SIEM/S3/OpenSearch backend (owner requirement); off-box shipping is the
 * separate {@link AuditForwarder} seam, invoked <b>after commit</b>.
 *
 * <p>
 * Every append links into the S9 tamper-evidence <b>hash chain</b> (FR-AUD-3):
 * {@code record_hash = SHA-256(prev_hash ‖ canonical(event))} where
 * {@code prev_hash} is the previous row's {@code record_hash} in {@code seq}
 * order (see {@link AuditRecordHash}). Because R2DBC inserts are concurrent
 * (and HA runs multiple CP writers), the chain is serialized per insert with a
 * transaction-scoped Postgres advisory lock: within one transaction take the
 * lock, read the current chain head, compute this row's hash, and insert. The
 * search/get paths are read-only and leave the chain verifiable
 * ({@link #verifyChain}).
 */
@Service
public class PostgresAuditEventStore implements AuditEventStore {

	private static final Logger LOG = LoggerFactory.getLogger(PostgresAuditEventStore.class);

	/** Transaction-scoped advisory-lock key serializing the chain ("SL_AUD_C"). */
	private static final long CHAIN_LOCK = 0x53_4C_5F_41_55_44_5F_43L;

	// Off-box shipping must never stall the audited request: bound the forward so a
	// hung/slow forwarder can't add unbounded latency (it fails best-effort
	// instead).
	private static final Duration FORWARD_TIMEOUT = Duration.ofSeconds(5);

	private static final String LATEST_HASH = "SELECT record_hash FROM runtime.audit_event "
			+ "WHERE record_hash IS NOT NULL ORDER BY seq DESC LIMIT 1";

	private final AuditEventRepository events;
	private final ObjectMapper objectMapper;
	private final DatabaseClient db;
	private final TransactionalOperator tx;
	private final AuditForwarder forwarder;

	public PostgresAuditEventStore(AuditEventRepository events, ObjectMapper objectMapper, DatabaseClient db,
			TransactionalOperator tx, AuditForwarder forwarder) {
		this.events = events;
		this.objectMapper = objectMapper;
		this.db = db;
		this.tx = tx;
		this.forwarder = forwarder;
	}

	@Override
	public Mono<Void> record(AuditRecord record) {
		return insert(record, detailNode(record.detail(), null, null));
	}

	@Override
	public Mono<Void> recordChange(String actor, String subject, String action, Map<String, String> detail,
			Object before, Object after) {
		return insert(AuditRecord.of(actor, subject, action, "success", null, null, detail),
				detailNode(detail, before, after));
	}

	private ObjectNode detailNode(Map<String, String> detail, Object before, Object after) {
		ObjectNode node = objectMapper.createObjectNode();
		if (detail != null) {
			detail.forEach(node::put);
		}
		if (before != null) {
			node.set("before", objectMapper.valueToTree(before));
		}
		if (after != null) {
			node.set("after", objectMapper.valueToTree(after));
		}
		return node;
	}

	// A node-label snapshot is stored as a jsonb OBJECT; an absent/empty map stays
	// null (matches the immortal null history + the "no labels known" deny path)
	// rather than an empty object, so a label-scoped auditor never matches it.
	private ObjectNode labelsNode(Map<String, String> labels) {
		if (labels == null || labels.isEmpty()) {
			return null;
		}
		ObjectNode node = objectMapper.createObjectNode();
		labels.forEach(node::put);
		return node;
	}

	private Mono<Void> insert(AuditRecord rec, ObjectNode detailNode) {
		// Truncate to microseconds so the value hashed equals the value that
		// round-trips from the timestamptz column (the chain must recompute exactly).
		Instant occurredAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
		AuditEvent event = AuditEvent.create(occurredAt, rec.actor(), rec.subject(), rec.action(), rec.outcome(),
				rec.correlationId(), rec.sessionId(), rec.nodeId(), labelsNode(rec.nodeLabels()), rec.sourceIp(),
				rec.accessModel(), rec.capabilities(), detailNode);
		Mono<AuditEvent> chainedInsert = db.sql("SELECT pg_advisory_xact_lock(:k)").bind("k", CHAIN_LOCK).fetch()
				.rowsUpdated()
				.then(db.sql(LATEST_HASH).map((row, meta) -> row.get("record_hash", String.class)).first()
						.defaultIfEmpty(AuditRecordHash.GENESIS))
				.flatMap(prevHash -> events
						.save(event.withChain(prevHash, AuditRecordHash.recordHash(prevHash, event))));
		// Ship off-box only AFTER the row commits, and never let a forward failure
		// roll back or surface on the audited action (best-effort, §15/NFR-5). A
		// failure/timeout is logged loudly (the event is already durably committed) —
		// never swallowed silently.
		return tx.transactional(chainedInsert)
				.flatMap(saved -> forwarder.forward(saved).timeout(FORWARD_TIMEOUT).onErrorResume(error -> {
					LOG.warn("audit off-box forward failed for {} (event is committed): {}", saved.id(),
							error.toString());
					return Mono.empty();
				}).thenReturn(saved)).then();
	}

	@Override
	public Mono<AuditPage> search(AuditQuery query) {
		int pageSize = CursorPages.clamp(query.limit());
		UUID afterId = CursorPages.decodeCursor(query.cursor());
		AuditSearchSql.Built built = AuditSearchSql.build(query, afterId, pageSize + 1, objectMapper);
		DatabaseClient.GenericExecuteSpec spec = db.sql(built.sql());
		for (Map.Entry<String, Object> param : built.params().entrySet()) {
			spec = spec.bind(param.getKey(), param.getValue());
		}
		return spec.map((row, meta) -> row.get("id", UUID.class)).all().collectList().flatMap(ids -> {
			boolean more = ids.size() > pageSize;
			List<UUID> pageIds = more ? List.copyOf(ids.subList(0, pageSize)) : ids;
			String next = more ? CursorPages.encodeCursor(pageIds.get(pageIds.size() - 1)) : null;
			if (pageIds.isEmpty()) {
				return Mono.just(new AuditPage(List.of(), null));
			}
			return events.findAllById(pageIds).collectMap(AuditEvent::id, Function.identity()).map(byId -> {
				// findAllById order is unspecified; restore the keyset (newest-first) order.
				List<AuditEvent> ordered = pageIds.stream().map(byId::get).filter(java.util.Objects::nonNull)
						.collect(Collectors.toList());
				return new AuditPage(ordered, next);
			});
		});
	}

	@Override
	public Mono<AuditEvent> findById(UUID id) {
		return events.findById(id);
	}

	@Override
	public Mono<AuditChainVerifier.Result> verifyChain() {
		return events.findChainOrdered().collectList().map(AuditChainVerifier::verify);
	}
}
