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
 * Service-account definition CRUD end to end (FR-AUTH-12): create/get/list/
 * update/delete over the generated interface, {@code user:manage} gated +
 * audited, pre-commit validation (422), cursor pagination and Idempotency-Key
 * replay. The definition NEVER carries a secret. Distinct from the runtime
 * {@code /v1/service-accounts/{id}/credentials} surface (AuthController).
 */
class ServiceAccountCrudIT extends AbstractConfigApiIT {

	private Map<String, Object> saBody(String name, String authMethod, String keyReference, Integer tokenTtlSeconds) {
		return Map.of("name", name, "description", "test account", "authMethod", authMethod, "keyReference",
				keyReference, "tokenTtlSeconds", tokenTtlSeconds);
	}

	@Test
	void createValidatesPersistsAndAudits() {
		String admin = "svc-sa-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.USER_MANAGE);
		String name = "sa-" + UUID.randomUUID();

		client.post().uri("/v1/service-accounts").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(saBody(name, "mtls", "jwks://issuer/keys", 3600))
				.exchange().expectStatus().isCreated().expectBody().jsonPath("$.id").isNotEmpty().jsonPath("$.name")
				.isEqualTo(name).jsonPath("$.authMethod").isEqualTo("mtls").jsonPath("$.tokenTtlSeconds")
				.isEqualTo(3600).jsonPath("$.origin").isEqualTo("api").jsonPath("$.version").isEqualTo(0)
				// the definition never carries an issued secret
				.jsonPath("$.clientSecret").doesNotExist().jsonPath("$.secret").doesNotExist();

		client.get().uri("/v1/service-accounts").header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isOk().expectBody().jsonPath("$.items").isArray();
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("service_account.create"));
	}

	@Test
	void createDefaultsAuthMethodWhenOmitted() {
		String token = tokenWith("svc-sa-def-" + UUID.randomUUID(), PlatformPermissions.USER_MANAGE);

		// auth_method is NOT NULL; an omitted authMethod defaults to private_key_jwt.
		client.post().uri("/v1/service-accounts").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("name", "sa-" + UUID.randomUUID())).exchange()
				.expectStatus().isCreated().expectBody().jsonPath("$.authMethod").isEqualTo("private_key_jwt")
				.jsonPath("$.origin").isEqualTo("api");
	}

	@Test
	void privateKeyMaterialRejectedPreCommit() {
		String token = tokenWith("svc-sa-priv-" + UUID.randomUUID(), PlatformPermissions.USER_MANAGE);

		client.post().uri("/v1/service-accounts").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(saBody("sa-" + UUID.randomUUID(), "private_key_jwt",
						"-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----", 3600))
				.exchange().expectStatus().isEqualTo(422).expectHeader()
				.contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON).expectBody().jsonPath("$.title")
				.isEqualTo("Invalid configuration").jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/validation-error");
	}

	@Test
	void nonPositiveTokenTtlRejectedPreCommit() {
		String token = tokenWith("svc-sa-ttl-" + UUID.randomUUID(), PlatformPermissions.USER_MANAGE);

		client.post().uri("/v1/service-accounts").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(saBody("sa-" + UUID.randomUUID(), "client_secret", "jwks://x", 0)).exchange().expectStatus()
				.isEqualTo(422).expectBody().jsonPath("$.title").isEqualTo("Invalid configuration");
	}

	@Test
	void writesAndReadsRequireUserManage() {
		String noneToken = tokenWith("svc-sa-none-" + UUID.randomUUID());
		client.post().uri("/v1/service-accounts").header("Authorization", "Bearer " + noneToken)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(saBody("sa-" + UUID.randomUUID(), "mtls", "jwks://x", 60)).exchange().expectStatus()
				.isForbidden();
		client.get().uri("/v1/service-accounts").header("Authorization", "Bearer " + noneToken).exchange()
				.expectStatus().isForbidden();

		String manage = tokenWith("svc-sa-mng-" + UUID.randomUUID(), PlatformPermissions.USER_MANAGE);
		client.get().uri("/v1/service-accounts").header("Authorization", "Bearer " + manage).exchange().expectStatus()
				.isOk();
	}

	@Test
	void getUpdateDeleteRoundTripWithOptimisticConcurrency() {
		String token = tokenWith("svc-sa-rt-" + UUID.randomUUID(), PlatformPermissions.USER_MANAGE);
		String name = "sa-" + UUID.randomUUID();
		String id = create(token, saBody(name, "mtls", "jwks://issuer/keys", 3600));

		client.get().uri("/v1/service-accounts/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.tokenTtlSeconds").isEqualTo(3600);

		// Correct version replaces mutable fields; name is immutable.
		client.put().uri("/v1/service-accounts/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("description", "updated", "authMethod", "client_secret", "keyReference", "jwks://new",
						"tokenTtlSeconds", 7200, "version", 0))
				.exchange().expectStatus().isOk().expectBody().jsonPath("$.tokenTtlSeconds").isEqualTo(7200)
				.jsonPath("$.authMethod").isEqualTo("client_secret").jsonPath("$.name").isEqualTo(name)
				.jsonPath("$.origin").isEqualTo("api").jsonPath("$.version").isEqualTo(1);

		// A PUT omitting the (NOT NULL) authMethod preserves it rather than nulling it.
		client.put().uri("/v1/service-accounts/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("description", "again", "tokenTtlSeconds", 7200, "version", 1)).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.authMethod").isEqualTo("client_secret")
				.jsonPath("$.version").isEqualTo(2);

		// A stale version is a 409.
		client.put().uri("/v1/service-accounts/" + id).header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(Map.of("description", "stale", "tokenTtlSeconds", 60, "version", 0)).exchange()
				.expectStatus().isEqualTo(409);

		client.delete().uri("/v1/service-accounts/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		// Idempotent delete + gone.
		client.delete().uri("/v1/service-accounts/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNoContent();
		client.get().uri("/v1/service-accounts/" + id).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNotFound();
	}

	@Test
	void idempotencyKeyReplaysAndRejectsBodyChange() {
		String token = tokenWith("svc-sa-idem-" + UUID.randomUUID(), PlatformPermissions.USER_MANAGE);
		String name = "sa-" + UUID.randomUUID();
		String key = "idem-" + UUID.randomUUID();
		Map<String, Object> body = saBody(name, "mtls", "jwks://issuer/keys", 3600);

		String firstId = client.post().uri("/v1/service-accounts").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();

		String replayId = client.post().uri("/v1/service-accounts").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange()
				.expectStatus().isCreated().returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
		assertThat(replayId).isEqualTo(firstId);

		// Same key + DIFFERENT body -> 422 idempotency conflict.
		client.post().uri("/v1/service-accounts").header("Authorization", "Bearer " + token)
				.header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON)
				.bodyValue(saBody(name, "mtls", "jwks://issuer/keys", 9999)).exchange().expectStatus().isEqualTo(422)
				.expectBody().jsonPath("$.type")
				.isEqualTo("https://docs.sessionlayer.example/problems/idempotency-key-conflict");
	}

	@Test
	void cursorPaginationReturnsAStableForwardCursor() {
		String token = tokenWith("svc-sa-page-" + UUID.randomUUID(), PlatformPermissions.USER_MANAGE);
		for (int i = 0; i < 3; i++) {
			create(token, saBody("sa-" + UUID.randomUUID(), "mtls", "jwks://x", 60));
		}

		@SuppressWarnings("unchecked")
		Map<String, Object> page1 = client.get().uri("/v1/service-accounts?limit=2")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
		assertThat(items1).hasSize(2);
		String next = (String) page1.get("nextCursor");
		assertThat(next).isNotBlank();

		@SuppressWarnings("unchecked")
		Map<String, Object> page2 = client.get().uri("/v1/service-accounts?limit=2&cursor=" + next)
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().returnResult(Map.class)
				.getResponseBody().blockFirst();
		List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
		assertThat(items2).isNotEmpty();
		List<Object> ids1 = items1.stream().map(m -> m.get("id")).toList();
		assertThat(items2.stream().map(m -> m.get("id"))).noneMatch(ids1::contains);

		client.get().uri("/v1/service-accounts?cursor=not-a-cursor").header("Authorization", "Bearer " + token)
				.exchange().expectStatus().isBadRequest();
	}

	private String create(String token, Map<String, Object> body) {
		return client.post().uri("/v1/service-accounts").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(body).exchange().expectStatus().isCreated()
				.returnResult(Map.class).getResponseBody().blockFirst().get("id").toString();
	}
}
