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
 * JIT-policy CRUD end to end (`config.jit_policy`, FR-ACC-3): create/get/list/
 * update/delete over the generated interface, {@code settings:write}-gated +
 * audited, pre-commit validation of the TTL and approval chain (422), cursor
 * pagination, optimistic concurrency, and Idempotency-Key replay.
 */
class JitPolicyCrudIT extends AbstractConfigApiIT {

	private Map<String, Object> body(String name, int ttl) {
		return Map.of("name", name, "targetSelector", Map.of("env", Map.of("op", "eq", "value", "prod")),
				"capabilities", List.of("shell", "exec"), "maxTtlSeconds", ttl, "approvalChain",
				List.of(Map.of("kind", "email", "value", "boss@example.com")));
	}

	@Test
	void createValidatesPersistsAndAudits() {
		String admin = "svc-jit-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "jit-" + UUID.randomUUID();

		client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(name, 3600)).exchange().expectStatus()
				.isCreated().expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.name").isEqualTo(name)
				.jsonPath("$.origin").isEqualTo("api").jsonPath("$.version").isEqualTo(0).jsonPath("$.maxTtlSeconds")
				.isEqualTo(3600).jsonPath("$.approvalChain[0].kind").isEqualTo("email")
				.jsonPath("$.approvalChain[0].value").isEqualTo("boss@example.com");

		client.get().uri("/v1/jit-policies").header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("jit_policy.create"));
	}

	@Test
	void invalidConfigRejectedPreCommit() {
		String admin = "svc-jit-invalid-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);

		// A non-positive TTL is a semantic (pre-commit) 422.
		client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body("jit-" + UUID.randomUUID(), 0)).exchange()
				.expectStatus().isEqualTo(422).expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid configuration").jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/validation-error");

		// An approval level with a blank value is likewise a 422.
		client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", "jit-" + UUID.randomUUID(), "targetSelector", Map.of(), "capabilities",
						List.of(), "maxTtlSeconds", 3600, "approvalChain",
						List.of(Map.of("kind", "email", "value", ""))))
				.exchange().expectStatus().isEqualTo(422);
	}

	@Test
	void allOpsRequireSettingsWrite() {
		String none = "svc-jit-none-" + UUID.randomUUID();
		String noneToken = tokenWith(none);
		client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + noneToken)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body("jit-" + UUID.randomUUID(), 60)).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/jit-policies").header("Authorization", "Bearer " + noneToken).exchange().expectStatus()
				.isForbidden();

		String admin = "svc-jit-rw-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body("jit-" + UUID.randomUUID(), 60)).exchange()
				.expectStatus().isCreated();
		client.get().uri("/v1/jit-policies").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk();
	}

	@Test
	void getUpdateDeleteRoundTripWithOptimisticConcurrency() {
		String admin = "svc-jit-rt-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "jit-" + UUID.randomUUID();

		String id = create(token, body(name, 3600));

		client.get().uri("/v1/jit-policies/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.maxTtlSeconds").isEqualTo(3600);

		// Update with the correct version replaces mutable fields; the name is
		// immutable.
		client.put().uri("/v1/jit-policies/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(
						Map.of("targetSelector", Map.of("env", Map.of("op", "eq", "value", "staging")), "capabilities",
								List.of("sftp"), "maxTtlSeconds", 7200, "approvalChain", List.of(), "version", 0))
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.maxTtlSeconds").isEqualTo(7200)
				.jsonPath("$.name").isEqualTo(name).jsonPath("$.version").isEqualTo(1);

		client.put().uri("/v1/jit-policies/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("targetSelector", Map.of(), "capabilities",
						List.of(), "maxTtlSeconds", 100, "approvalChain", List.of(), "version", 0))
				.exchange().expectStatus().isEqualTo(409);

		client.delete().uri("/v1/jit-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.delete().uri("/v1/jit-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.get().uri("/v1/jit-policies/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNotFound();
	}

	@Test
	void duplicateNameConflicts() {
		String admin = "svc-jit-dup-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "jit-" + UUID.randomUUID();

		create(token, body(name, 3600));
		client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(name, 3600)).exchange().expectStatus()
				.isEqualTo(409);
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String admin = "svc-jit-idem-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "jit-" + UUID.randomUUID();
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = body(name, 3600);

		String firstId = client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		String replayId = client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);

		client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + token).header("Idempotency-Key", key)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(name, 999)).exchange().expectStatus()
				.isEqualTo(422).expectBody().jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String admin = "svc-jit-page-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		for (int i = 0; i < 3; i++) {
			create(token, body("jit-" + UUID.randomUUID(), 60));
		}

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/jit-policies?limit=2")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/jit-policies?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		client.get().uri("/v1/jit-policies?cursor=not-a-cursor").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isBadRequest();
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/jit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}
}
