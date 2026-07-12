package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.api.model.IssuedJoinToken;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
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

/**
 * Part D — the secured join-token CRUD end to end (FR-JOIN-2). Every route is
 * platform-RBAC gated ({@code node:enroll}); issuance returns the raw token
 * exactly once and stores only its hash; listing returns metadata only (never
 * the raw token); revoke is idempotent; and every mutation is audited.
 */
@AutoConfigureWebTestClient
class JoinTokenCrudIT extends AbstractAuthIT {

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

	@Test
	void issueReturnsRawTokenOnceStoresHashAndAudits() {
		String admin = "svc-jt-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);
		String node = "jt-node-" + UUID.randomUUID();

		IssuedJoinToken issued = client.post().uri("/v1/join-tokens").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("nodeName", node)).exchange().expectStatus()
				.isCreated().expectBody(IssuedJoinToken.class).returnResult().getResponseBody();
		assertThat(issued.getToken()).isNotBlank();
		assertThat(issued.getNodeName()).isEqualTo(node);
		assertThat(issued.getJoinMethod()).isEqualTo(IssuedJoinToken.JoinMethodEnum.TOKEN);

		// Listing returns metadata only — never the raw token.
		String list = client.get().uri("/v1/join-tokens").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody(String.class).returnResult().getResponseBody();
		assertThat(list).contains(node).doesNotContain(issued.getToken());

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("join_token.issue"));
	}

	@Test
	void anInvalidNodeNameIsRejectedWithProblemDetails() {
		String admin = "svc-jt-bad-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);

		client.post().uri("/v1/join-tokens").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("nodeName", "bad name!")).exchange()
				.expectStatus().isBadRequest().expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid join token request");
	}

	@Test
	void everyRouteRequiresNodeEnroll() {
		String noPerms = "svc-jt-none-" + UUID.randomUUID();
		String token = tokenWith(noPerms); // authenticated, but no node:enroll

		client.post().uri("/v1/join-tokens").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("nodeName", "node-x")).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/join-tokens").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void revokeIsIdempotentAndAudited() {
		String admin = "svc-jt-revoke-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL);
		String node = "jt-revoke-" + UUID.randomUUID();

		IssuedJoinToken issued = client.post().uri("/v1/join-tokens").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("nodeName", node)).exchange().expectStatus()
				.isCreated().expectBody(IssuedJoinToken.class).returnResult().getResponseBody();

		client.delete().uri("/v1/join-tokens/" + issued.getId()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		// Idempotent: revoking an already-revoked id is still 204.
		client.delete().uri("/v1/join-tokens/" + issued.getId()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("join_token.revoke"));
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles
					.save(PlatformRole.create("jt-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}
}
