package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.data.config.JitPolicy;
import io.sessionlayer.controlplane.data.config.JitPolicyRepository;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * The secured JIT REST surface end to end (FR-ACC-2/3/4). Submit is open to any
 * authenticated principal; approve/deny are `request:approve`-gated;
 * self-approval is forbidden (403) even for a `request:approve` holder.
 */
@AutoConfigureWebTestClient
class JitCrudIT extends AbstractAuthIT {

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
	NodeRepository nodes;
	@Autowired
	JitPolicyRepository policies;
	@Autowired
	ObjectMapper mapper;

	@Test
	void submitPendsThenApproverActivates() {
		String zone = unique();
		UUID node = seedNode(zone);
		String approver = "boss-" + unique() + "@corp";
		seedPolicy(zone, approver);
		String requester = "svc-jit-req-" + UUID.randomUUID();
		String reqToken = tokenWith(requester); // any authenticated principal may submit

		@SuppressWarnings("rawtypes")
		Map created = client.post().uri("/v1/jit-requests").header("Authorization", "Bearer " + reqToken)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("targetNodeId", node.toString(), "principal", "deploy", "reason", "prod fix"))
				.exchange().expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst();
		org.assertj.core.api.Assertions.assertThat(created).containsEntry("state", "PENDING_APPROVAL")
				.containsEntry("requester", requester);
		String id = created.get("id").toString();

		String apToken = tokenWith(approver, PlatformPermissions.REQUEST_APPROVE);
		client.post().uri("/v1/jit-requests/" + id + "/approve").header("Authorization", "Bearer " + apToken)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("reason", "ok")).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.state").isEqualTo("APPROVED");
	}

	@Test
	void selfApprovalIsForbidden() {
		String zone = unique();
		UUID node = seedNode(zone);
		seedPolicy(zone, "boss-" + unique() + "@corp");
		String requester = "svc-jit-self-" + UUID.randomUUID();
		// The requester holds request:approve, but still cannot approve their OWN
		// request.
		String token = tokenWith(requester, PlatformPermissions.REQUEST_APPROVE);

		String id = client.post().uri("/v1/jit-requests").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("targetNodeId", node.toString(), "principal", "deploy", "reason", "self")).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		client.post().uri("/v1/jit-requests/" + id + "/approve").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of()).exchange().expectStatus().isForbidden();
	}

	@Test
	void listAndReadRequireRequestApprove() {
		String noPerms = tokenWith("svc-jit-none-" + UUID.randomUUID());
		client.get().uri("/v1/jit-requests").header("Authorization", "Bearer " + noPerms).exchange().expectStatus()
				.isForbidden();
	}

	// A per-test zone label so exactly one JIT policy governs this test's node
	// (this
	// class shares one Postgres with the other AbstractAuthIT ITs).
	private UUID seedNode(String zone) {
		ObjectNode labels = mapper.createObjectNode().put("env", "prod").put("jitzone", zone);
		return nodes
				.save(Node.create("node-" + UUID.randomUUID(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedPolicy(String zone, String approverEmail) {
		ObjectNode targetSelector = mapper.createObjectNode();
		targetSelector.set("jitzone", mapper.createObjectNode().put("op", "eq").put("value", zone));
		var chain = mapper.createArrayNode();
		chain.add(mapper.createObjectNode().put("kind", "email").put("value", approverEmail));
		policies.save(JitPolicy.create("jit-" + UUID.randomUUID(), targetSelector, List.of("shell", "exec"), 3600,
				chain, "api")).block();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles
					.save(PlatformRole.create("jit-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}
}
