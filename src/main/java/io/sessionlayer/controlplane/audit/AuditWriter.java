package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Thin append-only writer for the correlated audit stream
 * ({@code runtime.audit_event}, Design §12.2). The mTLS identity + signing
 * paths emit through this so an enroll/renew/sign is a first-class audit
 * record. INSERT only — the table is append-only (a DB trigger rejects
 * UPDATE/DELETE), so this never mutates an existing row. No key material is
 * ever recorded (only fingerprints/ids).
 */
@Service
public class AuditWriter {

	private final AuditEventRepository events;
	private final ObjectMapper objectMapper;

	public AuditWriter(AuditEventRepository events, ObjectMapper objectMapper) {
		this.events = events;
		this.objectMapper = objectMapper;
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
		AuditEvent event = AuditEvent.create(Instant.now(), actor, subject, action, outcome, null, sessionId, nodeId,
				null, null, null, null, detailNode);
		return events.save(event).then();
	}
}
