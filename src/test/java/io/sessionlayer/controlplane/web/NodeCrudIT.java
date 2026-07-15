package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.node.JsonNodeFactory;

/**
 * Part E — the secured {@code /v1/nodes} CRUD end to end (Design §9/§12A;
 * FR-NODE-1/2/3). Every route is platform-RBAC gated (node:enroll /
 * node:quarantine / node:remove); agentless enrollment refuses TOFU (400) and a
 * duplicate name (409); quarantine raises a pushed node-Lock; remove
 * soft-deletes and revokes an agent node's credential; and every mutation is
 * audited. Provisioning is a pure API flow (closes the S15 dev-seed gap): a
 * node is registered AND a join token issued via the API, never SQL.
 */
@AutoConfigureWebTestClient
class NodeCrudIT extends AbstractAuthIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final SecureRandom RANDOM = new SecureRandom();

	@Autowired
	WebTestClient client;
	@Autowired
	MachineIdentityService machineIdentity;
	@Autowired
	ServiceAccountRepository serviceAccounts;
	@Autowired
	PlatformRoleRepository roles;
	@Autowired
	RoleBindingRepository bindings;
	@Autowired
	AuditEventRepository auditEvents;
	@Autowired
	NodeRepository nodes;
	@Autowired
	AgentIdentityRepository agentIdentities;
	@Autowired
	AccessLockRepository accessLocks;

	@Test
	void registerAgentlessValidatesPersistsAndAudits() {
		String admin = "svc-node-reg-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);
		String name = "web-" + unique();

		client.post().uri("/v1/nodes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", name, "address", "10.0.0.5:22", "labels", Map.of("env", "prod"),
						"pinnedHostKey", pinnedHostKeyLine()))
				.exchange().expectStatus().isCreated().expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.name")
				.isEqualTo(name).jsonPath("$.connectorKind").isEqualTo("agentless").jsonPath("$.status")
				.isEqualTo("active").jsonPath("$.address").isEqualTo("10.0.0.5:22").jsonPath("$.labels.env")
				.isEqualTo("prod");

		// It is listable, and left an audit trail.
		String list = client.get().uri("/v1/nodes").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody(String.class).returnResult().getResponseBody();
		assertThat(list).contains(name);
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("node.register"));
	}

	@Test
	void registerWithoutAHostAnchorIsRejectedNoTofu() {
		String admin = "svc-node-tofu-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);

		// No hostCertificate and no pinnedHostKey — an agentless node with no
		// enrollment-anchored host identity would be un-verifiable (§9.3), so it is a
		// 400.
		client.post().uri("/v1/nodes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", "web-" + unique(), "address", "10.0.0.9:22")).exchange().expectStatus()
				.isBadRequest().expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON)
				.expectBody().jsonPath("$.title").isEqualTo("Node request rejected");
	}

	@Test
	void registeringADuplicateNameConflicts() {
		String admin = "svc-node-dup-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);
		String name = "web-" + unique();

		registerAgentless(token, name).expectStatus().isCreated();
		// The unique(name) constraint is the race-safe dedup — a duplicate is a 409.
		registerAgentless(token, name).expectStatus().isEqualTo(409);
	}

	@Test
	void getReturnsTheNodeAndUnknownIsNotFound() {
		String admin = "svc-node-get-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);
		String name = "web-" + unique();
		String id = register(token, name);

		client.get().uri("/v1/nodes/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.name").isEqualTo(name);
		client.get().uri("/v1/nodes/" + UUID.randomUUID()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNotFound();
	}

	@Test
	void quarantineRaisesANodeLockAndAudits() {
		String admin = "svc-node-quar-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL, PlatformPermissions.NODE_QUARANTINE);
		String id = register(token, "web-" + unique());

		client.post().uri("/v1/nodes/" + id + "/quarantine").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("reason", "incident-42", "existingSessions", "kill")).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.status").isEqualTo("quarantined").jsonPath("$.statusReason")
				.isEqualTo("incident-42");

		// A node-scoped Lock was raised (deny-wins, pushed to Gateways).
		assertThat(nodeLock(UUID.fromString(id))).isNotNull().satisfies(lock -> {
			assertThat(lock.mode()).isEqualTo("strict"); // kill → strict
			assertThat(lock.reason()).isEqualTo("incident-42");
		});
		assertThat(auditEvents.findByActor(admin).collectList().block())
				.anySatisfy(e -> assertThat(e.action()).isEqualTo("node.quarantine"));
	}

	@Test
	void releaseQuarantineClearsTheLockAndReactivates() {
		String admin = "svc-node-rel-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL, PlatformPermissions.NODE_QUARANTINE);
		UUID id = UUID.fromString(register(token, "web-" + unique()));

		client.post().uri("/v1/nodes/" + id + "/quarantine").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("reason", "incident", "existingSessions", "drain")).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.status").isEqualTo("quarantined");
		// drain → best_effort lock.
		assertThat(nodeLock(id).mode()).isEqualTo("best_effort");

		client.delete().uri("/v1/nodes/" + id + "/quarantine").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.status").isEqualTo("active");
		assertThat(nodeLock(id)).isNull(); // the quarantine lock was released
		// Idempotent: releasing an un-quarantined node still succeeds.
		client.delete().uri("/v1/nodes/" + id + "/quarantine").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk();
		assertThat(auditEvents.findByActor(admin).collectList().block())
				.anySatisfy(e -> assertThat(e.action()).isEqualTo("node.quarantine.release"));
	}

	@Test
	void removeSoftDeletesExcludesFromListAndIsIdempotent() {
		String admin = "svc-node-rm-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL, PlatformPermissions.NODE_REMOVE);
		String name = "web-" + unique();
		String id = register(token, name);

		client.delete().uri("/v1/nodes/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNoContent();
		// Idempotent: removing an already-removed node is still 204.
		client.delete().uri("/v1/nodes/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNoContent();

		// Soft-remove: the row survives (status 'removed') but is excluded from the
		// list.
		assertThat(nodes.findById(UUID.fromString(id)).block().status()).isEqualTo("removed");
		String list = client.get().uri("/v1/nodes").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody(String.class).returnResult().getResponseBody();
		assertThat(list).doesNotContain(name);
		assertThat(auditEvents.findByActor(admin).collectList().block())
				.anySatisfy(e -> assertThat(e.action()).isEqualTo("node.remove"));
	}

	@Test
	void removingAnAgentNodeRevokesItsCredential() {
		String admin = "svc-node-revoke-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_REMOVE);
		// An agent node + its active mTLS identity (agent nodes join; seed directly).
		Node node = nodes.save(
				Node.create("agent-" + unique(), null, JSON.objectNode(), "agent", "active", "healthy", null, null))
				.block();
		agentIdentities.save(AgentIdentity.create(node.id(), "mtls:seed-" + unique(), "SHA256:seed", 0, "token",
				"active", Instant.now(), Instant.now().plus(24, ChronoUnit.HOURS))).block();

		client.delete().uri("/v1/nodes/" + node.id()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();

		// The identity is flipped off active, and a covering clone-Lock carrying BOTH
		// the
		// node and the agent-id facet is raised so a stale clone is refused on both
		// planes.
		assertThat(agentIdentities.findByNodeIdAndStatus(node.id(), "active").block()).isNull();
		assertThat(agentIdentities.findByNodeId(node.id()).blockFirst().status()).isEqualTo("revoked");
		assertThat(accessLocks.findAll().collectList().block()).anySatisfy(lock -> {
			JsonNode selector = lock.targetSelector();
			assertThat(facet(selector, "node_ids")).contains(node.id().toString());
			assertThat(facet(selector, "identities")).isNotEmpty();
		});
		assertThat(auditEvents.findByActor(admin).collectList().block())
				.anySatisfy(e -> assertThat(e.action()).isEqualTo("agent.revoke"));
	}

	@Test
	void everyRouteIsPlatformRbacGated() {
		String id = register(tokenWith("svc-node-seed-" + unique(), PlatformPermissions.NODE_ENROLL),
				"web-" + unique());
		String none = tokenWith("svc-node-none-" + unique()); // authenticated, no node permissions

		client.post().uri("/v1/nodes").header("Authorization", "Bearer " + none).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", "web-" + unique(), "address", "10.0.0.1:22", "pinnedHostKey",
						pinnedHostKeyLine()))
				.exchange().expectStatus().isForbidden();
		client.get().uri("/v1/nodes").header("Authorization", "Bearer " + none).exchange().expectStatus().isForbidden();
		client.delete().uri("/v1/nodes/" + id).header("Authorization", "Bearer " + none).exchange().expectStatus()
				.isForbidden();

		// node:enroll alone cannot quarantine or remove — those need their own
		// permission.
		String enrollOnly = tokenWith("svc-node-enroll-" + unique(), PlatformPermissions.NODE_ENROLL);
		client.post().uri("/v1/nodes/" + id + "/quarantine").header("Authorization", "Bearer " + enrollOnly)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("reason", "x")).exchange().expectStatus()
				.isForbidden();
		client.delete().uri("/v1/nodes/" + id).header("Authorization", "Bearer " + enrollOnly).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void provisioningANodeAndAJoinTokenViaApiClosesTheDevSeedGap() {
		// The closes-F-ha-e2e-devseed-1 gate: an agentless node AND an agent join
		// token,
		// both provisioned purely via the API (no SQL), each audited.
		String admin = "svc-node-prov-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);

		String agentless = "host-" + unique();
		registerAgentless(token, agentless).expectStatus().isCreated();

		String agentNode = "web-" + unique();
		client.post().uri("/v1/join-tokens").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("nodeName", agentNode)).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.token").isNotEmpty().jsonPath("$.nodeName")
				.isEqualTo(agentNode);

		List<String> actions = auditEvents.findByActor(admin).collectList().block().stream().map(AuditEvent::action)
				.toList();
		assertThat(actions).contains("node.register", "join_token.issue");
	}

	// ----- helpers -----

	private String register(String token, String name) {
		return registerAgentless(token, name).expectStatus().isCreated().returnResult(Map.class).getResponseBody()
				.blockFirst().get("id").toString();
	}

	private WebTestClient.ResponseSpec registerAgentless(String token, String name) {
		return client.post().uri("/v1/nodes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", name, "address", "10.0.0.5:22", "pinnedHostKey", pinnedHostKeyLine()))
				.exchange();
	}

	private AccessLock nodeLock(UUID nodeId) {
		return accessLocks.findAll().collectList().block().stream()
				.filter(lock -> facet(lock.targetSelector(), "node_ids").equals(List.of(nodeId.toString()))).findFirst()
				.orElse(null);
	}

	private static List<String> facet(JsonNode selector, String key) {
		JsonNode array = selector == null ? null : selector.get(key);
		if (array == null || !array.isArray()) {
			return List.of();
		}
		List<String> values = new java.util.ArrayList<>();
		for (JsonNode element : array) {
			values.add(element.asString());
		}
		return values;
	}

	private static String pinnedHostKeyLine() {
		byte[] blob = new byte[48];
		RANDOM.nextBytes(blob);
		return "ecdsa-sha2-nistp256 " + Base64.getEncoder().encodeToString(blob) + " host@example";
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles.save(
					PlatformRole.create("node-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
