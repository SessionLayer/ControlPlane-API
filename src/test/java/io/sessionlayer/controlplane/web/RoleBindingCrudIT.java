package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Role-binding CRUD end to end (FR-PADM-2): create/get/list/update/delete over
 * the generated interface, RBAC-gated + audited, pre-commit validation of the
 * role FK (422), cursor pagination, and Idempotency-Key replay. Follows
 * {@link RuleCrudIT}.
 */
class RoleBindingCrudIT extends AbstractConfigApiIT {

	@Autowired
	private PlatformRoleRepository platformRoles;

	private UUID seedRole() {
		return platformRoles
				.save(PlatformRole.create("role-" + UUID.randomUUID(), List.of("rbac:read"), "test", "default")).block()
				.id();
	}

	private Map<String, Object> bindingBody(UUID roleId, String subject, Map<String, Object> scope) {
		return Map.of("roleId", roleId.toString(), "subjectKind", "user", "subject", subject, "scope", scope);
	}

	@Test
	void createValidatesPersistsAndAudits() {
		String admin = "svc-rb-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE, PlatformPermissions.RBAC_READ);
		UUID roleId = seedRole();
		String subject = "user-" + UUID.randomUUID();

		client.post().uri("/v1/role-bindings").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(bindingBody(roleId, subject, Map.of("nodeLabels", Map.of("env", "prod")))).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.roleId")
				.isEqualTo(roleId.toString()).jsonPath("$.subject").isEqualTo(subject).jsonPath("$.origin")
				.isEqualTo("api").jsonPath("$.version").isEqualTo(0);

		client.get().uri("/v1/role-bindings").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("role_binding.create"));
	}

	@Test
	void unknownRoleIdRejectedPreCommit() {
		String admin = "svc-rb-invalid-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE);

		// The roleId FK is checked pre-commit: an unknown role is a 422 problem+json.
		client.post().uri("/v1/role-bindings").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(bindingBody(UUID.randomUUID(), "user-" + UUID.randomUUID(), Map.of())).exchange()
				.expectStatus().isEqualTo(422).expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid configuration").jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/validation-error");
	}

	@Test
	void writesRequireRbacWriteReadsRequireRbacRead() {
		String reader = "svc-rb-reader-" + UUID.randomUUID();
		String readToken = tokenWith(reader, PlatformPermissions.RBAC_READ);

		client.post().uri("/v1/role-bindings").header("Authorization", "Bearer " + readToken)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(bindingBody(UUID.randomUUID(), "user-" + UUID.randomUUID(), Map.of())).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/role-bindings").header("Authorization", "Bearer " + readToken).exchange().expectStatus()
				.isOk();

		String none = "svc-rb-none-" + UUID.randomUUID();
		String noneToken = tokenWith(none);
		client.get().uri("/v1/role-bindings").header("Authorization", "Bearer " + noneToken).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void getUpdateDeleteRoundTripWithOptimisticConcurrency() {
		String admin = "svc-rb-rt-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE, PlatformPermissions.RBAC_READ);
		UUID roleId = seedRole();
		String subject = "user-" + UUID.randomUUID();

		String id = create(token, bindingBody(roleId, subject, Map.of("env", "prod")));

		client.get().uri("/v1/role-bindings/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.scope.env").isEqualTo("prod");

		// Update replaces the (only mutable) scope + bumps version; subject/role are
		// fixed.
		client.put().uri("/v1/role-bindings/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("scope", Map.of("env", "staging"), "version", 0)).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.scope.env").isEqualTo("staging").jsonPath("$.subject").isEqualTo(subject)
				.jsonPath("$.version").isEqualTo(1);

		// A stale version is a 409.
		client.put().uri("/v1/role-bindings/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("scope", Map.of(), "version", 0)).exchange()
				.expectStatus().isEqualTo(409);

		client.delete().uri("/v1/role-bindings/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		// Idempotent delete + gone.
		client.delete().uri("/v1/role-bindings/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.get().uri("/v1/role-bindings/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNotFound();
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String admin = "svc-rb-idem-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE);
		UUID roleId = seedRole();
		String subject = "user-" + UUID.randomUUID();
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = bindingBody(roleId, subject, Map.of("env", "prod"));

		String firstId = client.post().uri("/v1/role-bindings").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		// Same key + same body -> the ORIGINAL response replayed, no second create.
		String replayId = client.post().uri("/v1/role-bindings").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);

		// Same key + DIFFERENT body -> 422 idempotency conflict.
		client.post().uri("/v1/role-bindings").header("Authorization", "Bearer " + token).header("Idempotency-Key", key)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(bindingBody(roleId, subject, Map.of("env", "dev")))
				.exchange().expectStatus().isEqualTo(422).expectBody().jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String admin = "svc-rb-page-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE, PlatformPermissions.RBAC_READ);
		UUID roleId = seedRole();
		for (int i = 0; i < 3; i++) {
			create(token, bindingBody(roleId, "user-" + UUID.randomUUID(), Map.of()));
		}

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/role-bindings?limit=2")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/role-bindings?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		// Keyset: page 2 shares no id with page 1 (no OFFSET drift / overlap).
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		// A malformed cursor is a 400.
		client.get().uri("/v1/role-bindings?cursor=not-a-cursor").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isBadRequest();
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/role-bindings").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}
}
