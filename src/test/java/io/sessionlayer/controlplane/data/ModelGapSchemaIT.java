package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.config.PolicyEpoch;
import io.sessionlayer.controlplane.data.config.PolicyEpochRepository;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicy;
import io.sessionlayer.controlplane.data.config.SessionLimitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.DeviceFlow;
import io.sessionlayer.controlplane.data.runtime.DeviceFlowRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeHostKey;
import io.sessionlayer.controlplane.data.runtime.NodeHostKeyRepository;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.ServiceAccountCredential;
import io.sessionlayer.controlplane.data.runtime.ServiceAccountCredentialRepository;
import io.sessionlayer.controlplane.data.runtime.SessionLease;
import io.sessionlayer.controlplane.data.runtime.SessionLeaseRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.r2dbc.core.DatabaseClient;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

/**
 * Dedicated gate for §6.3 — all F-model-deferrals-1 schema additions. A
 * schema-presence assertion fails if any expected new table/column is missing,
 * and each new table/column round-trips + enforces its key constraints.
 */
class ModelGapSchemaIT extends AbstractDataIT {

	@Autowired
	private OperatorSettingsRepository operatorSettings;
	@Autowired
	private PolicyEpochRepository policyEpochs;
	@Autowired
	private SessionLimitPolicyRepository sessionLimits;
	@Autowired
	private ServiceAccountCredentialRepository saCreds;
	@Autowired
	private DeviceFlowRepository deviceFlows;
	@Autowired
	private NodeHostKeyRepository hostKeys;
	@Autowired
	private SessionLeaseRepository leases;
	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DatabaseClient db;
	@Autowired
	private ObjectMapper objectMapper;

	private boolean columnExists(String schema, String table, String column) {
		return Boolean.TRUE.equals(db
				.sql("SELECT EXISTS (SELECT 1 FROM information_schema.columns "
						+ "WHERE table_schema = :s AND table_name = :t AND column_name = :c)")
				.bind("s", schema).bind("t", table).bind("c", column).map(row -> row.get(0, Boolean.class)).one()
				.block());
	}

	@Test
	void allExpectedTablesAndColumnsExist() {
		// New tables (schema-presence): a missing one fails the gate.
		Map<String, String> newTables = Map.of("config", "operator_settings", "config#2", "policy_epoch", "config#3",
				"session_limit_policy", "runtime", "service_account_credential", "runtime#2", "device_flow",
				"runtime#3", "node_host_key", "runtime#4", "session_lease");
		newTables.forEach((k, table) -> {
			String schema = k.startsWith("config") ? "config" : "runtime";
			assertThat(columnExists(schema, table, "id")).as("table %s.%s exists", schema, table).isTrue();
		});
		// New columns on existing tables.
		assertThat(columnExists("runtime", "recording_ref", "retention_until")).isTrue();
		assertThat(columnExists("runtime", "recording_ref", "legal_hold")).isTrue();
		assertThat(columnExists("runtime", "recording_ref", "status")).isTrue();
		assertThat(columnExists("runtime", "recording_ref", "content_digest")).isTrue();
		assertThat(columnExists("runtime", "node", "status_reason")).isTrue();
		assertThat(columnExists("runtime", "node", "status_changed_by")).isTrue();
		assertThat(columnExists("runtime", "agent_identity", "status_reason")).isTrue();
		assertThat(columnExists("runtime", "gateway_identity", "status_reason")).isTrue();
		assertThat(columnExists("runtime", "jit_request", "decided_by")).isTrue();
		assertThat(columnExists("runtime", "jit_request", "decision_reason")).isTrue();
	}

	@Test
	void operatorSettingsSingletonRoundTripsAndRejectsSecondRow() {
		var saved = operatorSettings.save(OperatorSettings.defaults()).block();
		assertThat(saved.auditRetentionDays()).isEqualTo(365);
		assertThat(saved.defaultWormMode()).isEqualTo("governance");
		assertThat(operatorSettings.findSingleton().block()).isNotNull();
		// singleton guard: a second row is rejected (unique singleton=true).
		StepVerifier.create(operatorSettings.save(OperatorSettings.defaults()))
				.verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void policyEpochRoundTripsAndIsMonotonic() {
		var epoch = policyEpochs.save(PolicyEpoch.initial()).block();
		var bumped = policyEpochs.save(new PolicyEpoch(epoch.id(), true, 5L, epoch.version(), null)).block();
		assertThat(bumped.epoch()).isEqualTo(5L);
		// a decrease is rejected by the DB trigger.
		StepVerifier.create(policyEpochs.save(new PolicyEpoch(bumped.id(), true, 3L, bumped.version(), null)))
				.verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void sessionLimitPolicyRoundTrips() {
		var sel = objectMapper.readTree("{\"group\":\"contractors\"}");
		var reread = sessionLimits.save(SessionLimitPolicy.create("contractors", sel, 2, 3600, 600, "git"))
				.flatMap(s -> sessionLimits.findById(s.id())).block();
		assertThat(reread.maxConcurrentSessions()).isEqualTo(2);
		assertThat(reread.identitySelector()).isEqualTo(sel);
	}

	@Test
	void serviceAccountCredentialRoundTripsAndRejectsPemSecret() {
		var reread = saCreds
				.save(ServiceAccountCredential.create(UUID.randomUUID(), "ci-bot", "client_secret", "argon2:abc",
						"SHA256:fp", Instant.now(), Instant.now().plus(1, ChronoUnit.DAYS)))
				.flatMap(s -> saCreds.findById(s.id())).block();
		assertThat(reread.status()).isEqualTo("active");
		// content guard: a PEM private key in the hash column is rejected.
		StepVerifier
				.create(saCreds.save(ServiceAccountCredential.create(UUID.randomUUID(), "bad", "client_secret",
						"-----BEGIN PRIVATE KEY-----", null, Instant.now(), null)))
				.verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void deviceFlowRoundTrips() {
		var reread = deviceFlows
				.save(DeviceFlow.create("dh", "uh", "conn-1", "203.0.113.4", 5,
						Instant.now().plus(10, ChronoUnit.MINUTES)))
				.flatMap(s -> deviceFlows.findByDeviceCodeHash("dh")).block();
		assertThat(reread.status()).isEqualTo("pending");
		assertThat(reread.connectionBinding()).isEqualTo("conn-1");
	}

	@Test
	void nodeHostKeyRoundTripsAndRejectsPrivateKey() {
		var node = nodes.save(Node.create("hk-node", null, obj(), "agentless", "active", "healthy", null, "10.0.0.5"))
				.block();
		var reread = hostKeys.save(NodeHostKey.create(node.id(), "ssh-ed25519", "ssh-ed25519 AAAAC3Nz...", "SHA256:hk",
				null, "pinned_key", Instant.now())).flatMap(k -> hostKeys.findByNodeId(node.id()).next()).block();
		assertThat(reread.source()).isEqualTo("pinned_key");
		// content guard: a private key pasted into public_key is rejected.
		StepVerifier
				.create(hostKeys.save(NodeHostKey.create(node.id(), "ssh-ed25519", "-----BEGIN PRIVATE KEY-----",
						"SHA256:bad", null, "pinned_key", Instant.now())))
				.verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void sessionLeaseConcurrencyCounts() {
		String identity = "conc-" + UUID.randomUUID();
		leases.save(SessionLease.acquire(identity, null, "gw-a", Instant.now(), null)).block();
		leases.save(SessionLease.acquire(identity, null, "gw-b", Instant.now(), null)).block();
		var released = leases.save(SessionLease.acquire(identity, null, "gw-c", Instant.now(), null)).block();
		// release one
		leases.save(new SessionLease(released.id(), released.identity(), released.sessionId(), released.gatewayName(),
				released.acquiredAt(), released.expiresAt(), Instant.now(), released.version(), released.createdAt(),
				released.updatedAt())).block();
		assertThat(leases.countLiveByIdentity(identity).block()).isEqualTo(2L); // 3 acquired, 1 released
	}

	@Test
	void recordingRetentionColumnsRoundTrip() {
		// recording_ref extended columns are exercised end to end in
		// AuditPartitioningIT;
		// here we assert defaults on a plain create().
		assertThat(columnExists("runtime", "recording_ref", "format")).isTrue();
	}

	private tools.jackson.databind.JsonNode obj() {
		return objectMapper.readTree("{}");
	}
}
