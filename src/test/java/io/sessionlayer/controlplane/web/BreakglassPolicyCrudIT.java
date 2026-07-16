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
 * Break-glass-policy CRUD end to end (`config.breakglass_policy`, FR-ACC-6):
 * create/get/list/update/delete over the generated interface,
 * {@code breakglass:manage}-gated + audited, fail-safe defaults for the omitted
 * safety toggles, cursor pagination, optimistic concurrency, and
 * Idempotency-Key replay.
 */
class BreakglassPolicyCrudIT extends AbstractConfigApiIT {

	private Map<String, Object> body(String name) {
		return Map.of("name", name, "alertTarget", "pagerduty://oncall");
	}

	@Test
	void createDefaultsFailSafePersistsAndAudits() {
		String admin = "svc-bg-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);
		String name = "bg-" + UUID.randomUUID();

		// Omitted toggles fail SAFE: recording strict + review required on, fido2 path.
		client.post().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(name)).exchange().expectStatus().isCreated()
				.expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.name").isEqualTo(name).jsonPath("$.origin")
				.isEqualTo("api").jsonPath("$.version").isEqualTo(0).jsonPath("$.recordingStrict").isEqualTo(true)
				.jsonPath("$.reviewRequired").isEqualTo(true).jsonPath("$.authPath").isEqualTo("fido2");

		client.get().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("breakglass_policy.create"));
	}

	@Test
	void explicitTogglesHonored() {
		String admin = "svc-bg-explicit-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);
		String name = "bg-" + UUID.randomUUID();

		client.post().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", name, "alertTarget", "slack://sec", "recordingStrict", false,
						"reviewRequired", false, "authPath", "offline_code"))
				.exchange().expectStatus().isCreated().expectBody().jsonPath("$.recordingStrict").isEqualTo(false)
				.jsonPath("$.reviewRequired").isEqualTo(false).jsonPath("$.authPath").isEqualTo("offline_code");
	}

	@Test
	void allOpsRequireBreakglassManage() {
		String none = "svc-bg-none-" + UUID.randomUUID();
		String noneToken = tokenWith(none);
		client.post().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + noneToken)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body("bg-" + UUID.randomUUID())).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + noneToken).exchange()
				.expectStatus().isForbidden();

		// settings:write does NOT grant break-glass management — it is its own
		// permission.
		String settings = "svc-bg-settings-" + UUID.randomUUID();
		String settingsToken = tokenWith(settings, PlatformPermissions.SETTINGS_WRITE);
		client.get().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + settingsToken).exchange()
				.expectStatus().isForbidden();

		String admin = "svc-bg-rw-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);
		client.post().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body("bg-" + UUID.randomUUID())).exchange()
				.expectStatus().isCreated();
		client.get().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk();
	}

	@Test
	void getUpdateDeleteRoundTripWithOptimisticConcurrency() {
		String admin = "svc-bg-rt-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);
		String name = "bg-" + UUID.randomUUID();

		String id = create(token, body(name));

		client.get().uri("/v1/breakglass-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.authPath").isEqualTo("fido2");

		// Update replaces mutable fields; the name is immutable.
		client.put().uri("/v1/breakglass-policies/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("alertTarget", "slack://sec", "recordingStrict", false, "reviewRequired", true,
						"authPath", "offline_code", "version", 0))
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.recordingStrict").isEqualTo(false)
				.jsonPath("$.authPath").isEqualTo("offline_code").jsonPath("$.name").isEqualTo(name)
				.jsonPath("$.version").isEqualTo(1);

		client.put().uri("/v1/breakglass-policies/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("alertTarget", "x", "version", 0)).exchange()
				.expectStatus().isEqualTo(409);

		client.delete().uri("/v1/breakglass-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.delete().uri("/v1/breakglass-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.get().uri("/v1/breakglass-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNotFound();
	}

	@Test
	void duplicateNameConflicts() {
		String admin = "svc-bg-dup-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);
		String name = "bg-" + UUID.randomUUID();

		create(token, body(name));
		client.post().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(name)).exchange().expectStatus().isEqualTo(409);
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String admin = "svc-bg-idem-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);
		String name = "bg-" + UUID.randomUUID();
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = body(name);

		String firstId = client.post().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		String replayId = client.post().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);

		client.post().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", name, "alertTarget", "email://sec")).exchange().expectStatus().isEqualTo(422)
				.expectBody().jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String admin = "svc-bg-page-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.BREAKGLASS_MANAGE);
		for (int i = 0; i < 3; i++) {
			create(token, body("bg-" + UUID.randomUUID()));
		}

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/breakglass-policies?limit=2")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/breakglass-policies?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		client.get().uri("/v1/breakglass-policies?cursor=not-a-cursor").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isBadRequest();
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/breakglass-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}
}
