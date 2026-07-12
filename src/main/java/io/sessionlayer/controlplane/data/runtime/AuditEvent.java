package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

/**
 * RUNTIME · {@code runtime.audit_event} (Design §12.2 / FR-AUD-9). The single
 * correlated audit stream shared by the SSH trail and the web/admin trail.
 * <b>Append-only</b> (a DB trigger rejects UPDATE/DELETE/TRUNCATE) and
 * <b>FK-free</b> (immortal; correlation is by id value).
 * {@code prevHash}/{@code recordHash} are reserved for the S9 hash chain. There
 * is deliberately no {@code updatedAt}.
 */
@Table(schema = "runtime", name = "audit_event")
public record AuditEvent(@Id UUID id, Instant occurredAt, String actor, String subject, String action, String outcome,
		UUID correlationId, UUID sessionId, UUID nodeId, JsonNode nodeLabels, String sourceIp, String accessModel,
		List<String> capabilities, JsonNode detail, String prevHash, String recordHash, @Version Long version,
		@CreatedDate Instant createdAt) {

	// The DB-assigned `seq` chain-order column (V3) is intentionally NOT mapped: it
	// is
	// GENERATED ALWAYS AS IDENTITY, so the ORM omits it from INSERT and Postgres
	// assigns it.

	public static AuditEvent create(Instant occurredAt, String actor, String subject, String action, String outcome,
			UUID correlationId, UUID sessionId, UUID nodeId, JsonNode nodeLabels, String sourceIp, String accessModel,
			List<String> capabilities, JsonNode detail) {
		return new AuditEvent(Uuids.v7(), occurredAt, actor, subject, action, outcome, correlationId, sessionId, nodeId,
				nodeLabels, sourceIp, accessModel, capabilities, detail, null, null, null, null);
	}

	/**
	 * Stamp the S9 hash-chain columns just before insert (the writer computes
	 * them).
	 */
	public AuditEvent withChain(String prevHash, String recordHash) {
		return new AuditEvent(id, occurredAt, actor, subject, action, outcome, correlationId, sessionId, nodeId,
				nodeLabels, sourceIp, accessModel, capabilities, detail, prevHash, recordHash, version, createdAt);
	}
}
