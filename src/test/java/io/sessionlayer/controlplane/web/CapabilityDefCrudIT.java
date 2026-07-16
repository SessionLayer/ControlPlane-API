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
 * Capability-catalogue CRUD end to end (`config.capability_def`, Design §12A):
 * create/get/list/update/delete over the generated interface,
 * {@code settings:write}-gated + audited, cursor pagination, optimistic
 * concurrency, and Idempotency-Key replay.
 *
 * <p>
 * {@code name} is a fixed 8-value capability enum with a UNIQUE constraint, and
 * the IT suite shares one Postgres with no per-test reset — so each method
 * DELETES what it creates to keep the small namespace free for the next
 * (methods run sequentially).
 */
class CapabilityDefCrudIT extends AbstractConfigApiIT {

	private Map<String, Object> body(String name, String description) {
		return Map.of("name", name, "description", description);
	}

	@Test
	void createValidatesPersistsAndAudits() {
		String admin = "svc-cap-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);

		@SuppressWarnings("unchecked")
		Map<String, Object> created = client.post().uri("/v1/capability-defs")
				.header("Authorization", "Bearer " + token).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(body("shell", "Interactive shell")).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst();
		assertThat(created.get("name")).isEqualTo("shell");
		assertThat(created.get("origin")).isEqualTo("api");
		assertThat(created.get("version")).isEqualTo(0);
		String id = created.get("id").toString();

		client.get().uri("/v1/capability-defs").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("capability_def.create"));

		delete(token, id);
	}

	@Test
	void allOpsRequireSettingsWrite() {
		String none = "svc-cap-none-" + UUID.randomUUID();
		String noneToken = tokenWith(none);
		client.post().uri("/v1/capability-defs").header("Authorization", "Bearer " + noneToken)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body("exec", "x")).exchange().expectStatus()
				.isForbidden();
		client.get().uri("/v1/capability-defs").header("Authorization", "Bearer " + noneToken).exchange().expectStatus()
				.isForbidden();

		String admin = "svc-cap-rw-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String id = create(token, body("exec", "Non-interactive exec"));
		client.get().uri("/v1/capability-defs").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk();
		delete(token, id);
	}

	@Test
	void getUpdateDeleteRoundTripWithOptimisticConcurrency() {
		String admin = "svc-cap-rt-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);

		String id = create(token, body("sftp", "SFTP subsystem"));

		client.get().uri("/v1/capability-defs/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.description").isEqualTo("SFTP subsystem");

		// Only description is mutable; the enum name is immutable and preserved.
		client.put().uri("/v1/capability-defs/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("description", "SFTP file transfer", "version", 0)).exchange().expectStatus().isOk()
				.expectBody().jsonPath("$.description").isEqualTo("SFTP file transfer").jsonPath("$.name")
				.isEqualTo("sftp").jsonPath("$.version").isEqualTo(1);

		client.put().uri("/v1/capability-defs/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("description", "stale", "version", 0))
				.exchange().expectStatus().isEqualTo(409);

		client.delete().uri("/v1/capability-defs/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.delete().uri("/v1/capability-defs/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.get().uri("/v1/capability-defs/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNotFound();
	}

	@Test
	void duplicateNameConflicts() {
		String admin = "svc-cap-dup-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);

		String id = create(token, body("x11", "X11 forwarding"));
		client.post().uri("/v1/capability-defs").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body("x11", "again")).exchange().expectStatus()
				.isEqualTo(409);
		delete(token, id);
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String admin = "svc-cap-idem-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = body("scp", "SCP copy");

		String firstId = client.post().uri("/v1/capability-defs").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		String replayId = client.post().uri("/v1/capability-defs").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);

		client.post().uri("/v1/capability-defs").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(body("scp", "different")).exchange().expectStatus().isEqualTo(422).expectBody()
				.jsonPath("$.type").isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");

		delete(token, firstId);
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String admin = "svc-cap-page-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String a = create(token, body("shell", "a"));
		String b = create(token, body("exec", "b"));
		String c = create(token, body("sftp", "c"));

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/capability-defs?limit=2")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/capability-defs?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		client.get().uri("/v1/capability-defs?cursor=not-a-cursor").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isBadRequest();

		delete(token, a);
		delete(token, b);
		delete(token, c);
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/capability-defs").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}

	private void delete(String token, String id) {
		client.delete().uri("/v1/capability-defs/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
	}
}
