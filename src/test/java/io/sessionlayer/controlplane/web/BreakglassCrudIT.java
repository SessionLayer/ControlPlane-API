package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.ca.wire.SshWriter;
import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivation;
import io.sessionlayer.controlplane.data.runtime.BreakglassActivationRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.MediaType;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * The secured break-glass management REST surface end to end (FR-ACC-6). All
 * routes are `breakglass:manage`-gated; raw offline codes are returned exactly
 * once; an activation's mandatory review is recorded.
 */
@AutoConfigureWebTestClient
class BreakglassCrudIT extends AbstractAuthIT {

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
	BreakglassActivationRepository activations;

	@Test
	void registerListAndRevokeCredential() {
		String admin = "svc-bg-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);
		String publicKey = Base64.getEncoder().encodeToString(skBlob((byte) 0x51));

		@SuppressWarnings("rawtypes")
		Map created = client.post().uri("/v1/breakglass/credentials").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(
						Map.of("publicKey", publicKey, "identity", "root@corp", "allowedPrincipals", List.of("root")))
				.exchange().expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst();
		assertThat(created.get("keyFingerprint").toString()).startsWith("SHA256:");
		String id = created.get("id").toString();

		client.get().uri("/v1/breakglass/credentials").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.credentials[?(@.id=='" + id + "')].identity")
				.isEqualTo("root@corp");

		// Revoke is idempotent (204 twice).
		client.delete().uri("/v1/breakglass/credentials/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.delete().uri("/v1/breakglass/credentials/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
	}

	@Test
	void issueOfflineCodesReturnsRawOnceAndListHidesThem() {
		String admin = "svc-bg-codes-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);

		client.post().uri("/v1/breakglass/offline-codes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("identity", "root@corp", "allowedPrincipals", List.of("root"), "count", 3)).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.codes.length()").isEqualTo(3)
				.jsonPath("$.codes[0]").isNotEmpty();

		// The list projection is metadata only — never the raw code.
		client.get().uri("/v1/breakglass/offline-codes").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.offlineCodes").isArray()
				.jsonPath("$.offlineCodes[0].code").doesNotExist();
	}

	@Test
	void managementRequiresBreakglassManage() {
		String token = tokenWith("svc-bg-none-" + UUID.randomUUID());
		client.get().uri("/v1/breakglass/credentials").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isForbidden();
		client.post().uri("/v1/breakglass/offline-codes").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("identity", "x", "allowedPrincipals", List.of("root"))).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void reviewsAnActivation() {
		String admin = "svc-bg-review-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);
		BreakglassActivation activation = activations
				.save(BreakglassActivation.activate("root@corp", "root", "break-glass", "audit:breakglass.activated",
						null, null, "203.0.113.9", null, "SHA256:cred", Instant.now()))
				.block();

		client.post().uri("/v1/breakglass/activations/" + activation.id() + "/review")
				.header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("note", "reviewed post-incident")).exchange().expectStatus().isOk().expectBody()
				.jsonPath("$.reviewStatus").isEqualTo("reviewed").jsonPath("$.reviewer").isEqualTo(admin);

		client.get().uri("/v1/breakglass/activations?reviewStatus=reviewed").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.activations").isArray();
	}

	private static byte[] skBlob(byte fill) {
		byte[] q = new byte[65];
		q[0] = 0x04;
		for (int i = 1; i < q.length; i++) {
			q[i] = fill;
		}
		return new SshWriter().writeString("sk-ecdsa-sha2-nistp256@openssh.com").writeString("nistp256").writeString(q)
				.writeString("ssh:").toByteArray();
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles
					.save(PlatformRole.create("bg-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}
}
