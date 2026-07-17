package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.web.CursorPages;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * A second, list-backed {@link AuditEventStore} implementation used only in
 * tests to prove the Part B read path depends on the interface, not on Postgres
 * (the owner's audit-as-an-interface extensibility requirement). Append-only
 * with a faithful S9 hash chain, so {@link #verifyChain()} genuinely
 * recomputes; {@link #search} applies the same scalar/time/capability/label/
 * correlation filters + scope predicate + newest-first keyset the SQL backend
 * does. Not for production — no durability, no concurrency serialization beyond
 * the copy-on-write list.
 */
public final class InMemoryAuditEventStore implements AuditEventStore {

	private final List<AuditEvent> events = new CopyOnWriteArrayList<>();
	private final JsonMapper mapper = JsonMapper.builder().build();

	@Override
	public synchronized Mono<Void> record(AuditRecord rec) {
		ObjectNode node = mapper.createObjectNode();
		if (rec.detail() != null) {
			rec.detail().forEach(node::put);
		}
		return append(rec, node);
	}

	@Override
	public synchronized Mono<Void> recordChange(String actor, String subject, String action, Map<String, String> detail,
			Object before, Object after) {
		ObjectNode node = mapper.createObjectNode();
		if (detail != null) {
			detail.forEach(node::put);
		}
		if (before != null) {
			node.set("before", mapper.valueToTree(before));
		}
		if (after != null) {
			node.set("after", mapper.valueToTree(after));
		}
		return append(AuditRecord.of(actor, subject, action, "success", null, null, detail), node);
	}

	private Mono<Void> append(AuditRecord rec, ObjectNode detail) {
		Instant occurredAt = Instant.now().truncatedTo(ChronoUnit.MICROS);
		AuditEvent event = AuditEvent.create(occurredAt, rec.actor(), rec.subject(), rec.action(), rec.outcome(),
				rec.correlationId(), rec.sessionId(), rec.nodeId(), labelsNode(rec.nodeLabels()), rec.sourceIp(),
				rec.accessModel(), rec.capabilities(), detail);
		String prevHash = events.isEmpty() ? AuditRecordHash.GENESIS : events.get(events.size() - 1).recordHash();
		events.add(event.withChain(prevHash, AuditRecordHash.recordHash(prevHash, event)));
		return Mono.empty();
	}

	private JsonNode labelsNode(Map<String, String> labels) {
		if (labels == null || labels.isEmpty()) {
			return null;
		}
		ObjectNode node = mapper.createObjectNode();
		labels.forEach(node::put);
		return node;
	}

	@Override
	public Mono<AuditPage> search(AuditQuery query) {
		int pageSize = CursorPages.clamp(query.limit());
		UUID afterId = CursorPages.decodeCursor(query.cursor());
		List<AuditEvent> matched = events.stream().filter(e -> matches(e, query))
				.filter(e -> afterId == null || e.id().compareTo(afterId) < 0)
				.sorted(Comparator.comparing(AuditEvent::id).reversed()).limit(pageSize + 1L).toList();
		boolean more = matched.size() > pageSize;
		List<AuditEvent> page = more ? matched.subList(0, pageSize) : matched;
		String next = more ? CursorPages.encodeCursor(page.get(page.size() - 1).id()) : null;
		return Mono.just(new AuditPage(List.copyOf(page), next));
	}

	@Override
	public Mono<AuditEvent> findById(UUID id) {
		return Mono.justOrEmpty(events.stream().filter(e -> e.id().equals(id)).findFirst());
	}

	@Override
	public Mono<AuditChainVerifier.Result> verifyChain() {
		return Mono.just(AuditChainVerifier.verify(List.copyOf(events)));
	}

	private static boolean matches(AuditEvent e, AuditQuery q) {
		return eq(q.actor(), e.actor()) && eq(q.subject(), e.subject()) && eq(q.action(), e.action())
				&& eq(q.outcome(), e.outcome()) && eq(q.sourceIp(), e.sourceIp())
				&& eq(q.accessModel(), e.accessModel()) && eq(q.sessionId(), e.sessionId())
				&& eq(q.nodeId(), e.nodeId()) && eq(q.correlationId(), e.correlationId())
				&& withinFrom(q.from(), e.occurredAt()) && withinTo(q.to(), e.occurredAt())
				&& hasCapability(q.capability(), e.capabilities()) && hasLabels(q.nodeLabels(), e.nodeLabels())
				&& (q.scopeGrants().isEmpty() || AuditScopeMatcher.inScope(e, q.scopeGrants()));
	}

	private static boolean eq(String want, String have) {
		return want == null || want.isBlank() || want.equals(have);
	}

	private static boolean eq(UUID want, UUID have) {
		return want == null || want.equals(have);
	}

	private static boolean withinFrom(Instant from, Instant at) {
		return from == null || (at != null && !at.isBefore(from));
	}

	private static boolean withinTo(Instant to, Instant at) {
		return to == null || (at != null && at.isBefore(to));
	}

	private static boolean hasCapability(String capability, List<String> capabilities) {
		return capability == null || capability.isBlank()
				|| (capabilities != null && capabilities.contains(capability));
	}

	private static boolean hasLabels(Map<String, String> want, JsonNode have) {
		if (want.isEmpty()) {
			return true;
		}
		if (have == null || !have.isObject()) {
			return false;
		}
		for (Map.Entry<String, String> entry : want.entrySet()) {
			JsonNode value = have.get(entry.getKey());
			if (value == null || !value.isString() || !entry.getValue().equals(value.stringValue())) {
				return false;
			}
		}
		return true;
	}
}
