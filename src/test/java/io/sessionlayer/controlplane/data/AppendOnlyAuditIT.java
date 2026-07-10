package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

/**
 * Append-only {@code audit_event} (§4.6, §8.4) and secret-at-rest (§12)
 * enforcement. Immutability is enforced by a DB trigger, not by convention, so
 * UPDATE and DELETE are rejected even through the repository. Also proves the
 * one-correlated-stream join (FR-AUD-9) and that hash/reference-only columns
 * exist on secret-bearing tables.
 */
class AppendOnlyAuditIT extends AbstractDataIT {

	@Autowired
	private AuditEventRepository auditEvents;

	@Autowired
	private DatabaseClient db;

	@Autowired
	private ObjectMapper objectMapper;

	private AuditEvent sampleEvent(UUID correlationId) {
		return AuditEvent.create(Instant.now(), "admin@corp", "alice@corp", "jit.approve", "success", correlationId,
				null, null, objectMapper.readTree("{\"env\":\"prod\"}"), "203.0.113.7", "jit", List.of("shell", "exec"),
				objectMapper.readTree("{\"rule\":\"r1\"}"));
	}

	@Test
	void insertIsAllowed() {
		var saved = auditEvents.save(sampleEvent(UUID.randomUUID())).block();
		assertThat(saved).isNotNull();
		assertThat(auditEvents.findById(saved.id()).block()).isNotNull();
	}

	@Test
	void updateIsRejectedByTrigger() {
		var saved = auditEvents.save(sampleEvent(UUID.randomUUID())).block();
		// Non-null version -> Spring issues an UPDATE; the BEFORE UPDATE trigger
		// raises.
		var tampered = new AuditEvent(saved.id(), saved.occurredAt(), saved.actor(), saved.subject(), "TAMPERED",
				saved.outcome(), saved.correlationId(), saved.sessionId(), saved.nodeId(), saved.nodeLabels(),
				saved.sourceIp(), saved.accessModel(), saved.capabilities(), saved.detail(), saved.prevHash(),
				saved.recordHash(), saved.version(), saved.createdAt());
		StepVerifier.create(auditEvents.save(tampered)).verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void malformedSourceIpRejected() {
		var bad = AuditEvent.create(Instant.now(), "admin@corp", null, "login", "success", null, null, null, null,
				"not-an-ip", null, null, null);
		StepVerifier.create(auditEvents.save(bad)).verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void deleteIsRejectedByTrigger() {
		var saved = auditEvents.save(sampleEvent(UUID.randomUUID())).block();
		StepVerifier.create(auditEvents.deleteById(saved.id())).verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void truncateIsRejectedByTrigger() {
		StepVerifier.create(db.sql("TRUNCATE runtime.audit_event").fetch().rowsUpdated())
				.verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void oneCorrelatedStreamAcrossTrails() {
		UUID correlation = UUID.randomUUID();
		// A web/admin event (approval) and an SSH event share a correlation id
		// (FR-AUD-9).
		auditEvents.save(sampleEvent(correlation)).block();
		auditEvents
				.save(AuditEvent.create(Instant.now(), "alice@corp", "node-1", "ssh.connect", "success", correlation,
						UUID.randomUUID(), UUID.randomUUID(), null, "203.0.113.7", "jit", List.of("shell"), null))
				.block();
		assertThat(auditEvents.findByCorrelationId(correlation).collectList().block()).hasSize(2);
	}

	@Test
	void secretBearingTablesStoreHashesOrReferencesOnly() {
		var joinTokenCols = columnsOf("runtime", "join_token");
		assertThat(joinTokenCols).contains("token_hash").doesNotContain("token", "secret", "raw_token");

		var otpCols = columnsOf("runtime", "otp");
		assertThat(otpCols).contains("otp_hash").doesNotContain("secret", "raw_otp");

		// CA + recording store references, never key material.
		assertThat(columnsOf("config", "ca_config")).contains("key_reference").doesNotContain("private_key",
				"key_material", "key_pem");
		assertThat(columnsOf("runtime", "recording_ref")).contains("encryption_key_ref")
				.doesNotContain("encryption_key", "key_material");
	}

	private List<String> columnsOf(String schema, String table) {
		return db
				.sql("SELECT column_name FROM information_schema.columns "
						+ "WHERE table_schema = :s AND table_name = :t")
				.bind("s", schema).bind("t", table).map(row -> row.get("column_name", String.class)).all().collectList()
				.block();
	}
}
