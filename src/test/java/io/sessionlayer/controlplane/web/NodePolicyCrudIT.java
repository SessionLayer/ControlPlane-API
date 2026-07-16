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
 * Node-policy CRUD end to end (`config.node_policy`, Design §12A): create/get/
 * list/update/delete over the generated interface, {@code settings:write}-gated
 * + audited, pre-commit validation of host-trust refs (422), cursor pagination,
 * optimistic concurrency, and Idempotency-Key replay.
 */
class NodePolicyCrudIT extends AbstractConfigApiIT {

	private Map<String, Object> body(String name, String connectorKind) {
		return Map.of("name", name, "desiredLabels", Map.of("env", "prod"), "connectorKind", connectorKind);
	}

	@Test
	void createValidatesPersistsAndAudits() {
		String admin = "svc-np-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "np-" + UUID.randomUUID();

		client.post().uri("/v1/node-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(name, "agent")).exchange().expectStatus()
				.isCreated().expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.name").isEqualTo(name)
				.jsonPath("$.origin").isEqualTo("api").jsonPath("$.connectorKind").isEqualTo("agent")
				.jsonPath("$.version").isEqualTo(0);

		client.get().uri("/v1/node-policies").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("node_policy.create"));
	}

	@Test
	void hostTrustRefWithPrivateKeyRejectedPreCommit() {
		String admin = "svc-np-invalid-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);

		// A host-pin ref carrying inline key material is a semantic (pre-commit) 422.
		client.post().uri("/v1/node-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("name", "np-" + UUID.randomUUID(), "connectorKind", "agent", "hostPinRef",
						"-----BEGIN PRIVATE KEY-----\nMIIB"))
				.exchange().expectStatus().isEqualTo(422).expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid configuration").jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/validation-error");
	}

	@Test
	void allOpsRequireSettingsWrite() {
		String none = "svc-np-none-" + UUID.randomUUID();
		String noneToken = tokenWith(none);
		client.post().uri("/v1/node-policies").header("Authorization", "Bearer " + noneToken)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body("np-" + UUID.randomUUID(), "agent")).exchange()
				.expectStatus().isForbidden();
		client.get().uri("/v1/node-policies").header("Authorization", "Bearer " + noneToken).exchange().expectStatus()
				.isForbidden();

		String admin = "svc-np-rw-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		client.post().uri("/v1/node-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body("np-" + UUID.randomUUID(), "agent")).exchange()
				.expectStatus().isCreated();
		client.get().uri("/v1/node-policies").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk();
	}

	@Test
	void getUpdateDeleteRoundTripWithOptimisticConcurrency() {
		String admin = "svc-np-rt-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "np-" + UUID.randomUUID();

		String id = create(token, body(name, "agent"));

		client.get().uri("/v1/node-policies/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.connectorKind").isEqualTo("agent");

		// Update with the correct version flips the connector and bumps version; the
		// immutable name is preserved.
		client.put().uri("/v1/node-policies/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(
						Map.of("desiredLabels", Map.of("env", "staging"), "connectorKind", "agentless", "version", 0))
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.connectorKind").isEqualTo("agentless")
				.jsonPath("$.name").isEqualTo(name).jsonPath("$.version").isEqualTo(1);

		// A stale version is a 409.
		client.put().uri("/v1/node-policies/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("desiredLabels", Map.of(), "connectorKind", "agent", "version", 0)).exchange()
				.expectStatus().isEqualTo(409);

		client.delete().uri("/v1/node-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.delete().uri("/v1/node-policies/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.get().uri("/v1/node-policies/" + id).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isNotFound();
	}

	@Test
	void duplicateNameConflicts() {
		String admin = "svc-np-dup-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "np-" + UUID.randomUUID();

		create(token, body(name, "agent"));
		client.post().uri("/v1/node-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(name, "agent")).exchange().expectStatus()
				.isEqualTo(409);
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String admin = "svc-np-idem-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		String name = "np-" + UUID.randomUUID();
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = body(name, "agent");

		String firstId = client.post().uri("/v1/node-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		String replayId = client.post().uri("/v1/node-policies").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);

		// Same key + DIFFERENT body -> 422 idempotency conflict.
		client.post().uri("/v1/node-policies").header("Authorization", "Bearer " + token).header("Idempotency-Key", key)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body(name, "agentless")).exchange().expectStatus()
				.isEqualTo(422).expectBody().jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String admin = "svc-np-page-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.SETTINGS_WRITE);
		for (int i = 0; i < 3; i++) {
			create(token, body("np-" + UUID.randomUUID(), "agent"));
		}

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/node-policies?limit=2")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/node-policies?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		client.get().uri("/v1/node-policies?cursor=not-a-cursor").header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isBadRequest();
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/node-policies").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}
}
