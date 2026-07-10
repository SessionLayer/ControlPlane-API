package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;

/**
 * Dedicated gate for §6.2 — non-owner DB writer-role hardening (closes the
 * residual of F-append-only-1). The whole IT suite already connects R2DBC as
 * the restricted {@code cp_runtime} role (AbstractDataIT); this test proves the
 * append-only + schema-boundary guarantees hold against that <b>application
 * credential</b>, not merely the honest/ORM path the V4 trigger covers.
 *
 * <p>
 * Against the compromised-app-credential adversary the role MUST NOT be able to
 * {@code DROP}/{@code ALTER} a table, {@code ALTER TABLE ... DISABLE TRIGGER},
 * or {@code UPDATE}/{@code DELETE} {@code audit_event}; and MUST be able to
 * {@code INSERT} audit rows and do normal CRUD elsewhere.
 */
class WriterRoleIT extends AbstractDataIT {

	@Autowired
	private DatabaseClient db;

	@Autowired
	private AuditEventRepository audits;

	@Autowired
	private NodeRepository nodes;

	@Autowired
	private tools.jackson.databind.ObjectMapper objectMapper;

	private String currentUser() {
		return db.sql("SELECT current_user").map(row -> row.get(0, String.class)).one().block();
	}

	@Test
	void runtimeConnectsAsTheRestrictedNonSuperuserRole() {
		assertThat(currentUser()).isEqualTo("cp_runtime");
		Boolean isSuper = db.sql("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
				.map(row -> row.get(0, Boolean.class)).one().block();
		assertThat(isSuper).isFalse();
	}

	@Test
	void cannotDropOrAlterTables() {
		StepVerifier.create(db.sql("DROP TABLE runtime.node").then()).verifyError();
		StepVerifier.create(db.sql("ALTER TABLE runtime.node ADD COLUMN hacked text").then()).verifyError();
		// node still intact + writable.
		assertThat(nodes.count().block()).isNotNull();
	}

	@Test
	void cannotDisableTheAppendOnlyTrigger() {
		StepVerifier
				.create(db.sql("ALTER TABLE runtime.audit_event DISABLE TRIGGER audit_event_no_update_delete").then())
				.verifyError();
	}

	@Test
	void cannotUpdateOrDeleteAuditEvent() {
		audits.save(AuditEvent.create(Instant.now(), "writer-role", null, "probe", "success", null, null, null, null,
				null, null, null, null)).block();
		StepVerifier.create(db.sql("UPDATE runtime.audit_event SET actor = 'x'").then()).verifyError();
		StepVerifier.create(db.sql("DELETE FROM runtime.audit_event").then()).verifyError();
		// also refused directly against the current month's partition (defense in
		// depth).
		String part = "runtime.audit_event_" + java.time.YearMonth.now(java.time.ZoneOffset.UTC)
				.format(java.time.format.DateTimeFormatter.ofPattern("yyyyMM"));
		StepVerifier.create(db.sql("UPDATE " + part + " SET actor = 'x'").then()).verifyError();
	}

	@Test
	void canInsertAuditAndDoNormalCrud() {
		var e = audits.save(AuditEvent.create(Instant.now(), "writer-role-ok", null, "login", "success", null, null,
				null, null, null, null, null, null)).block();
		assertThat(audits.findById(e.id()).block()).isNotNull(); // INSERT + SELECT allowed

		var n = nodes.save(Node.create("writer-role-node", null, objectMapper.readTree("{}"), "agentless", "active",
				"healthy", null, "10.9.9.9")).block();
		var updated = nodes.save(new Node(n.id(), n.name(), n.nodePolicyName(), n.resolvedLabels(), n.connectorKind(),
				"quarantined", n.health(), n.owningGateway(), n.address(), "manual", "admin@x", Instant.now(),
				n.version(), n.createdAt(), n.updatedAt())).block();
		assertThat(updated.status()).isEqualTo("quarantined"); // UPDATE elsewhere allowed
	}
}
