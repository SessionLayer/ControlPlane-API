package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

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
 * Part G — the secured lock CRUD end to end (FR-LOCK-1/2). Platform-RBAC gates
 * every route ({@code lock:write}/{@code lock:read}); ingest validation rejects
 * an empty/typo'd target as an RFC-9457 400; a global lock needs an explicit
 * {@code all:true}; and every mutation is audited.
 */
@AutoConfigureWebTestClient
class LockCrudIT extends AbstractAuthIT {

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
	void createValidatesPersistsAndAudits() {
		String admin = "svc-lock-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.LOCK_WRITE, PlatformPermissions.LOCK_READ);

		client.post().uri("/v1/locks").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("target", Map.of("identities", List.of("alice")), "reason", "incident")).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.id").isNotEmpty()
				.jsonPath("$.target.identities[0]").isEqualTo("alice").jsonPath("$.createdBy").isEqualTo(admin);

		// It is listable (unexpired) and left an audit trail.
		client.get().uri("/v1/locks").header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.locks").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("lock.create"));
	}

	@Test
	void anEmptyTargetIsRejectedWithProblemDetails() {
		String admin = "svc-lock-empty-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.LOCK_WRITE);

		client.post().uri("/v1/locks").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("target", Map.of(), "reason", "oops"))
				.exchange().expectStatus().isBadRequest().expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid lock");
	}

	@Test
	void aGlobalLockRequiresExplicitAll() {
		String admin = "svc-lock-global-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.LOCK_WRITE);

		// all:false with no facet is not a valid global lock.
		client.post().uri("/v1/locks").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("target", Map.of("all", false), "reason", "typo")).exchange().expectStatus()
				.isBadRequest();

		// all:true is the intentional fleet-wide lock.
		client.post().uri("/v1/locks").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("target", Map.of("all", true), "reason", "full-shutdown")).exchange().expectStatus()
				.isCreated().expectBody().jsonPath("$.target.all").isEqualTo(true);
	}

	@Test
	void mutationsRequireLockWriteAndReadsRequireLockRead() {
		String noPerms = "svc-lock-none-" + UUID.randomUUID();
		String token = tokenWith(noPerms); // authenticated, but no lock permissions

		client.post().uri("/v1/locks").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("target", Map.of("all", true), "reason", "nope")).exchange().expectStatus()
				.isForbidden();
		client.get().uri("/v1/locks").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void releaseIsIdempotentAndAudited() {
		String admin = "svc-lock-release-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.LOCK_WRITE);

		String id = client.post().uri("/v1/locks").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("target", Map.of("identities", List.of("bob")), "reason", "incident")).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		client.delete().uri("/v1/locks/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNoContent();
		// Idempotent: releasing an already-released id is still 204.
		client.delete().uri("/v1/locks/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNoContent();

		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("lock.release"));
	}

	private String tokenWith(String saName, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		if (permissions.length > 0) {
			PlatformRole role = roles.save(
					PlatformRole.create("lock-role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
					.block();
			bindings.save(RoleBinding.create(role.id(), "user", saName, null, "default")).block();
		}
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}
}
