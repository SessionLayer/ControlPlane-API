package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.SessionLimitPolicyRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Session 25 Part A — session-limit-policy CRUD end to end (FR-SESS-3 /
 * FR-API-2/5) over the generated interface, following the {@link RuleCrudIT}
 * exemplar: RBAC-gated ({@code rbac:read} reads / {@code settings:write}
 * writes) + before/after audited, pre-commit validation (422 — malformed
 * selector, out-of-range limit, all-null limits), version-409, cursor
 * pagination, and Idempotency-Key replay.
 */
class SessionLimitPolicyCrudIT extends AbstractConfigApiIT {

	@Autowired
	private SessionLimitPolicyRepository policies;

	// session_limit_policy is DECISION-PATH config (Authorize resolves ceilings
	// from it); keep the shared container clean so a leftover policy can never
	// perturb another suite's authorization decision (S17 lesson).
	@AfterEach
	void resetPolicies() {
		policies.deleteAll().block();
	}

	private Map<String, Object> policyBody(String name, Object maxConcurrent, Object maxSeconds, Object idleSeconds) {
		Map<String, Object> body = new HashMap<>();
		body.put("name", name);
		body.put("identitySelector", Map.of("identities", List.of("alice")));
		if (maxConcurrent != null) {
			body.put("maxConcurrentSessions", maxConcurrent);
		}
		if (maxSeconds != null) {
			body.put("maxSessionSeconds", maxSeconds);
		}
		if (idleSeconds != null) {
			body.put("idleTimeoutSeconds", idleSeconds);
		}
		return body;
	}

	@Test
	void createValidatesPersistsAndAudits() {
		String admin = "svc-slp-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE, PlatformPermissions.RBAC_READ);
		String name = "slp-" + UUID.randomUUID();

		client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(policyBody(name, 2, 3600, 600)).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.name")
				.isEqualTo(name).jsonPath("$.origin").isEqualTo("api").jsonPath("$.maxConcurrentSessions").isEqualTo(2)
				.jsonPath("$.maxSessionSeconds").isEqualTo(3600).jsonPath("$.idleTimeoutSeconds").isEqualTo(600)
				.jsonPath("$.version").isEqualTo(0);

		client.get().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> {
			assertThat(e.action()).isEqualTo("session_limit_policy.create");
			// FR-PADM-3 before/after: a create has no before-state and a full after
			// snapshot.
			assertThat(e.detail().get("before")).isNull();
			assertThat(e.detail().get("after")).isNotNull();
			assertThat(e.detail().get("after").get("name").stringValue()).isEqualTo(name);
		});
	}

	@Test
	void invalidConfigRejectedPreCommit() {
		String admin = "svc-slp-invalid-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);

		// A malformed identitySelector (identities not a string array — a shape the
		// evaluator would quietly ignore, i.e. a policy limiting NO ONE) -> 422.
		Map<String, Object> badSelector = new HashMap<>(policyBody("slp-" + UUID.randomUUID(), 2, null, null));
		badSelector.put("identitySelector", Map.of("identities", "alice"));
		client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(badSelector).exchange().expectStatus().isEqualTo(422)
				.expectHeader().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody()
				.jsonPath("$.type").isEqualTo("https://docs.sessionlayer.example/problems/validation-error");

		// An out-of-range limit (0) -> 400/422 (schema minimum 1 + service floor).
		client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(policyBody("slp-" + UUID.randomUUID(), 0, null, null)).exchange().expectStatus()
				.value(status -> assertThat(status).isIn(400, 422));

		// All three limits absent is a silent no-op policy (dead config) -> 422.
		client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(policyBody("slp-" + UUID.randomUUID(), null, null, null)).exchange().expectStatus()
				.isEqualTo(422).expectBody().jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/validation-error");
	}

	@Test
	void writesRequireSettingsWriteReadsRequireRbacRead() {
		String reader = "svc-slp-reader-" + UUID.randomUUID();
		String readToken = tokenWith(reader, PlatformPermissions.RBAC_READ);

		// rbac:read may list but not write.
		client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + readToken)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(policyBody("slp-" + UUID.randomUUID(), 2, null, null)).exchange().expectStatus()
				.isForbidden();
		client.get().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + readToken).exchange()
				.expectStatus().isOk();

		// rbac:write is NOT enough for this surface (settings:write governs it).
		String rbacWriter = "svc-slp-rbacw-" + UUID.randomUUID();
		String rbacWriteToken = tokenWith(rbacWriter, PlatformPermissions.RBAC_WRITE);
		client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + rbacWriteToken)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(policyBody("slp-" + UUID.randomUUID(), 2, null, null)).exchange().expectStatus()
				.isForbidden();

		String none = "svc-slp-none-" + UUID.randomUUID();
		String noneToken = tokenWith(none);
		client.get().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + noneToken).exchange()
				.expectStatus().isForbidden();
	}

	@Test
	void getUpdateDeleteRoundTripWithOptimisticConcurrency() {
		String admin = "svc-slp-rt-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE, PlatformPermissions.RBAC_READ);
		String name = "slp-" + UUID.randomUUID();

		String id = create(token, policyBody(name, 2, 3600, null));

		client.get().uri("/v1/session-limit-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.maxConcurrentSessions").isEqualTo(2)
				.jsonPath("$.maxSessionSeconds").isEqualTo(3600);

		// Update with the correct version replaces the mutable fields (an omitted
		// maxSessionSeconds clears it — full replace, not merge) and bumps the
		// version.
		@SuppressWarnings("unchecked")
		Map<String, Object> updated = client.put().uri("/v1/session-limit-policies/" + id)
				.header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("identitySelector", Map.of("identities", List.of("alice")), "maxConcurrentSessions",
						5, "idleTimeoutSeconds", 900, "version", 0))
				.exchange().expectStatus().isOk().returnResult(Map.class).getResponseBody().blockFirst();
		assertThat(updated.get("maxConcurrentSessions")).isEqualTo(5);
		assertThat(updated.get("idleTimeoutSeconds")).isEqualTo(900);
		assertThat(updated.get("maxSessionSeconds")).isNull();
		assertThat(updated.get("name")).isEqualTo(name);
		assertThat(updated.get("version")).isEqualTo(1);

		// The update was audited with before/after states.
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> {
			assertThat(e.action()).isEqualTo("session_limit_policy.update");
			assertThat(e.detail().get("before")).isNotNull();
			assertThat(e.detail().get("after")).isNotNull();
			assertThat(e.detail().get("before").get("maxConcurrentSessions").intValue()).isEqualTo(2);
			assertThat(e.detail().get("after").get("maxConcurrentSessions").intValue()).isEqualTo(5);
		});

		// A stale version is a 409.
		client.put().uri("/v1/session-limit-policies/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("identitySelector",
						Map.of("identities", List.of("alice")), "maxConcurrentSessions", 9, "version", 0))
				.exchange().expectStatus().isEqualTo(409);

		client.delete().uri("/v1/session-limit-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		// Idempotent delete + gone.
		client.delete().uri("/v1/session-limit-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.get().uri("/v1/session-limit-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNotFound();
		assertThat(auditEvents.findByActor(admin).collectList().block())
				.anySatisfy(e -> assertThat(e.action()).isEqualTo("session_limit_policy.delete"));
	}

	@Test
	void duplicateNameIsAConflict() {
		String admin = "svc-slp-dup-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "slp-" + UUID.randomUUID();

		create(token, policyBody(name, 2, null, null));
		client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(policyBody(name, 3, null, null)).exchange()
				.expectStatus().isEqualTo(409);
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String admin = "svc-slp-idem-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "slp-" + UUID.randomUUID();
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = policyBody(name, 2, 3600, null);

		String firstId = client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		// Same key + same body -> the ORIGINAL response replayed, no second create.
		String replayId = client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);
		assertThat(policies.findAll().collectList().block()).hasSize(1);

		// Same key + DIFFERENT body -> 422 idempotency conflict.
		client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(policyBody(name, 9, null, null)).exchange().expectStatus().isEqualTo(422).expectBody()
				.jsonPath("$.type").isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String admin = "svc-slp-page-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE, PlatformPermissions.RBAC_READ);
		for (int i = 0; i < 3; i++) {
			create(token, policyBody("slp-" + UUID.randomUUID(), 2, null, null));
		}

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/session-limit-policies?limit=2")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/session-limit-policies?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		// Keyset: page 2 shares no id with page 1 (no OFFSET drift / overlap).
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		// A malformed cursor is a 400.
		client.get().uri("/v1/session-limit-policies?cursor=not-a-cursor").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isBadRequest();
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/session-limit-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}
}
