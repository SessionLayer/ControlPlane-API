package io.sessionlayer.controlplane.security;

import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
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
 * The REST security chain end to end (FR-AUTH-17): public probes open,
 * protected endpoints fail closed (401), the machine-token bearer path
 * authenticates, and platform-RBAC gates admin endpoints (403 without the
 * permission, 2xx with it).
 */
@AutoConfigureWebTestClient
class RestSecurityIT extends AbstractAuthIT {

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

	@Test
	void publicProbeIsOpenAndProtectedEndpointFailsClosed() {
		client.get().uri("/v1/healthz").exchange().expectStatus().isOk();
		// No credential → 401 (fail closed), never open.
		client.post().uri("/v1/otp").contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("identity", "x", "allowedPrincipals", List.of("deploy"))).exchange().expectStatus()
				.isUnauthorized();
	}

	@Test
	void machineTokenBearerIsGatedByPlatformRbac() {
		String sa = "svc-rest-" + UUID.randomUUID();
		String token = machineTokenFor(sa);

		// Authenticated but WITHOUT user:manage → 403 (default-deny).
		client.post().uri("/v1/otp").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("identity", "alice", "allowedPrincipals", List.of("deploy"))).exchange()
				.expectStatus().isForbidden();

		// Grant user:manage to the SA identity → the same call now succeeds (201).
		PlatformRole role = roles.save(PlatformRole.create("rest-admin-" + UUID.randomUUID(),
				List.of(PlatformPermissions.USER_MANAGE), "test", "default")).block();
		bindings.save(RoleBinding.create(role.id(), "user", sa, null, "default")).block();

		client.post().uri("/v1/otp").header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("identity", "alice", "allowedPrincipals", List.of("deploy"))).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.otp").isNotEmpty();
	}

	private String machineTokenFor(String saName) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}
}
