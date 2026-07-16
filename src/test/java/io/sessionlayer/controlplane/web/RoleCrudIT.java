package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/**
 * Platform-role CRUD end to end (FR-PADM-1): create/get/list/update/delete over
 * the generated interface, RBAC-gated + audited, pre-commit validation (422),
 * cursor pagination, and Idempotency-Key replay. Follows {@link RuleCrudIT}.
 */
class RoleCrudIT extends AbstractConfigApiIT {

	private Map<String, Object> roleBody(String name, List<String> permissions) {
		return Map.of("name", name, "permissions", permissions, "description", "test role");
	}

	@Test
	void createValidatesPersistsAndAudits() {
		String admin = "svc-role-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE, PlatformPermissions.RBAC_READ);
		String name = "role-" + UUID.randomUUID();

		client.post().uri("/v1/roles").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(roleBody(name, List.of("rbac:read", "audit:read")))
				.exchange().expectStatus().isCreated().expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.name")
				.isEqualTo(name).jsonPath("$.origin").isEqualTo("api").jsonPath("$.version").isEqualTo(0);

		client.get().uri("/v1/roles").header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("role.create"));
	}

	@Test
	void invalidConfigRejectedPreCommit() {
		String admin = "svc-role-invalid-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE);

		// A role must grant >=1 permission; an empty set is a pre-commit 422.
		client.post().uri("/v1/roles").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(roleBody("role-" + UUID.randomUUID(), List.of()))
				.exchange().expectStatus().isEqualTo(422).expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid configuration").jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/validation-error");
	}

	@Test
	void writesRequireRbacWriteReadsRequireRbacRead() {
		String reader = "svc-role-reader-" + UUID.randomUUID();
		String readToken = tokenWith(reader, PlatformPermissions.RBAC_READ);

		client.post().uri("/v1/roles").header("Authorization", "Bearer " + readToken)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(roleBody("role-" + UUID.randomUUID(), List.of("rbac:read"))).exchange().expectStatus()
				.isForbidden();
		client.get().uri("/v1/roles").header("Authorization", "Bearer " + readToken).exchange().expectStatus().isOk();

		String none = "svc-role-none-" + UUID.randomUUID();
		String noneToken = tokenWith(none);
		client.get().uri("/v1/roles").header("Authorization", "Bearer " + noneToken).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void getUpdateDeleteRoundTripWithOptimisticConcurrency() {
		String admin = "svc-role-rt-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE, PlatformPermissions.RBAC_READ);
		String name = "role-" + UUID.randomUUID();

		String id = create(token, roleBody(name, List.of("rbac:read", "rbac:write")));

		client.get().uri("/v1/roles/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.permissions").isArray();

		// Update with the correct version replaces permissions/description + bumps
		// version.
		client.put().uri("/v1/roles/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("permissions", List.of("rbac:read"), "description", "narrowed", "version", 0))
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.permissions[0]").isEqualTo("rbac:read")
				.jsonPath("$.description").isEqualTo("narrowed").jsonPath("$.version").isEqualTo(1);

		// A stale version is a 409.
		client.put().uri("/v1/roles/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("permissions", List.of("rbac:read"), "version", 0)).exchange().expectStatus()
				.isEqualTo(409);

		client.delete().uri("/v1/roles/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNoContent();
		// Idempotent delete + gone.
		client.delete().uri("/v1/roles/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNoContent();
		client.get().uri("/v1/roles/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNotFound();
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String admin = "svc-role-idem-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE);
		String name = "role-" + UUID.randomUUID();
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = roleBody(name, List.of("rbac:read"));

		String firstId = client.post().uri("/v1/roles").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		// Same key + same body -> the ORIGINAL response replayed, no second create.
		String replayId = client.post().uri("/v1/roles").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);

		// Same key + DIFFERENT body -> 422 idempotency conflict.
		client.post().uri("/v1/roles").header("Authorization", "Bearer " + token).header("Idempotency-Key", key)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(roleBody(name, List.of("audit:read"))).exchange()
				.expectStatus().isEqualTo(422).expectBody().jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String admin = "svc-role-page-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE, PlatformPermissions.RBAC_READ);
		for (int i = 0; i < 3; i++) {
			create(token, roleBody("role-" + UUID.randomUUID(), List.of("rbac:read")));
		}

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/roles?limit=2").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isOk().returnResult(Map.class).getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/roles?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		// Keyset: page 2 shares no id with page 1 (no OFFSET drift / overlap).
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		// A malformed cursor is a 400.
		client.get().uri("/v1/roles?cursor=not-a-cursor").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isBadRequest();
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/roles").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}
}
