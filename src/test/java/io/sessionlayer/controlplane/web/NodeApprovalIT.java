package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.api.model.NodeResource;
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
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * S16 Part D (T3 F3) — approval-required enrollment must not be a dead end.
 * With {@code sessionlayer.node.enrollment-approval-required=true} a registered
 * node starts {@code pending} (excluded from targeting) and is promoted to
 * {@code active} by the release/activate route (DELETE
 * {@code /v1/nodes/{id}/quarantine}). This is the ONLY transition off
 * {@code pending}, so without it the knob strands nodes.
 */
@AutoConfigureWebTestClient
@TestPropertySource(properties = "sessionlayer.node.enrollment-approval-required=true")
class NodeApprovalIT extends AbstractAuthIT {

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

	@Test
	void approvalRequiredEnrollmentStartsPendingAndIsActivatedByRelease() {
		String admin = "svc-node-appr-" + unique();
		String token = tokenWith(admin, PlatformPermissions.NODE_ENROLL, PlatformPermissions.NODE_QUARANTINE);
		String name = "web-" + unique();

		// Approval on → the node starts PENDING (excluded from targeting).
		NodeResource pending = client.post().uri("/v1/nodes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", name, "address", "10.0.0.5:22", "pinnedHostKey", pinnedHostKeyLine()))
				.exchange().expectStatus().isCreated().expectBody(NodeResource.class).returnResult().getResponseBody();
		assertThat(pending.getStatus()).isEqualTo(NodeResource.StatusEnum.PENDING);

		// Release/activate promotes pending → active (a DISTINCT audit action).
		NodeResource activated = client.delete().uri("/v1/nodes/" + pending.getId() + "/quarantine")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody(NodeResource.class).returnResult().getResponseBody();
		assertThat(activated.getStatus()).isEqualTo(NodeResource.StatusEnum.ACTIVE);

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("node.activate"));
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles.save(
					PlatformRole.create("appr-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}

	private static String pinnedHostKeyLine() {
		byte[] blob = new byte[48];
		RANDOM.nextBytes(blob);
		return "ecdsa-sha2-nistp256 " + Base64.getEncoder().encodeToString(blob) + " host@example";
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
