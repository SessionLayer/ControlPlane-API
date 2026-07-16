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
 * Part A exemplar — data-plane rule CRUD end to end (FR-API-2/5): create/get/
 * list/update/delete over the generated interface, RBAC-gated + audited,
 * pre-commit validation (422), cursor pagination, and Idempotency-Key replay.
 * The template the other Session 17 config CRUD ITs follow.
 */
class RuleCrudIT extends AbstractConfigApiIT {

	private Map<String, Object> ruleBody(String name, int ttl, String effect) {
		return Map.of("name", name, "identitySelector", Map.of("identities", List.of("alice")), "nodeLabelSelector",
				Map.of("env", Map.of("op", "eq", "value", "prod")), "principals", List.of("deploy"), "ttlSeconds", ttl,
				"capabilities", List.of("shell", "exec"), "effect", effect);
	}

	@Test
	void createValidatesPersistsAndAudits() {
		String admin = "svc-rule-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE, PlatformPermissions.RBAC_READ);
		String name = "rule-" + UUID.randomUUID();

		client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(ruleBody(name, 3600, "allow")).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.name")
				.isEqualTo(name).jsonPath("$.origin").isEqualTo("api").jsonPath("$.effect").isEqualTo("allow")
				.jsonPath("$.version").isEqualTo(0);

		client.get().uri("/v1/rules").header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("rule.create"));
	}

	@Test
	void invalidConfigRejectedPreCommit() {
		String admin = "svc-rule-invalid-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE);

		// ttlSeconds = 0 is a semantic (pre-commit) violation -> 422 problem+json.
		client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(ruleBody("rule-" + UUID.randomUUID(), 0, "allow"))
				.exchange().expectStatus().isEqualTo(422).expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid configuration").jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/validation-error");
	}

	@Test
	void writesRequireRbacWriteReadsRequireRbacRead() {
		String reader = "svc-rule-reader-" + UUID.randomUUID();
		String readToken = tokenWith(reader, PlatformPermissions.RBAC_READ);

		client.post().uri("/v1/rules").header("Authorization", "Bearer " + readToken)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(ruleBody("rule-" + UUID.randomUUID(), 60, "allow"))
				.exchange().expectStatus().isForbidden();
		client.get().uri("/v1/rules").header("Authorization", "Bearer " + readToken).exchange().expectStatus().isOk();

		String none = "svc-rule-none-" + UUID.randomUUID();
		String noneToken = tokenWith(none);
		client.get().uri("/v1/rules").header("Authorization", "Bearer " + noneToken).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void getUpdateDeleteRoundTripWithOptimisticConcurrency() {
		String admin = "svc-rule-rt-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE, PlatformPermissions.RBAC_READ);
		String name = "rule-" + UUID.randomUUID();

		String id = create(token, ruleBody(name, 3600, "allow"));

		client.get().uri("/v1/rules/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.ttlSeconds").isEqualTo(3600);

		// Update with the correct version bumps ttl and version.
		client.put().uri("/v1/rules/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("identitySelector", Map.of("identities", List.of("alice")), "nodeLabelSelector",
						Map.of("env", Map.of("op", "eq", "value", "prod")), "principals", List.of("deploy"),
						"ttlSeconds", 7200, "effect", "deny", "version", 0))
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.ttlSeconds").isEqualTo(7200)
				.jsonPath("$.effect").isEqualTo("deny").jsonPath("$.version").isEqualTo(1);

		// A stale version is a 409.
		client.put().uri("/v1/rules/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("identitySelector", Map.of(), "nodeLabelSelector", Map.of(), "principals",
						List.of("deploy"), "ttlSeconds", 100, "effect", "allow", "version", 0))
				.exchange().expectStatus().isEqualTo(409);

		client.delete().uri("/v1/rules/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNoContent();
		// Idempotent delete + gone.
		client.delete().uri("/v1/rules/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNoContent();
		client.get().uri("/v1/rules/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNotFound();
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String admin = "svc-rule-idem-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE);
		String name = "rule-" + UUID.randomUUID();
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = ruleBody(name, 3600, "allow");

		String firstId = client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		// Same key + same body -> the ORIGINAL response replayed, no second create.
		String replayId = client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);

		// Same key + DIFFERENT body -> 422 idempotency conflict.
		client.post().uri("/v1/rules").header("Authorization", "Bearer " + token).header("Idempotency-Key", key)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(ruleBody(name, 999, "allow")).exchange()
				.expectStatus().isEqualTo(422).expectBody().jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String admin = "svc-rule-page-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.RBAC_WRITE, PlatformPermissions.RBAC_READ);
		for (int i = 0; i < 3; i++) {
			create(token, ruleBody("rule-" + UUID.randomUUID(), 60, "allow"));
		}

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/rules?limit=2").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isOk().returnResult(Map.class).getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/rules?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		// Keyset: page 2 shares no id with page 1 (no OFFSET drift / overlap).
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		// A malformed cursor is a 400.
		client.get().uri("/v1/rules?cursor=not-a-cursor").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isBadRequest();
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/rules").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}
}
