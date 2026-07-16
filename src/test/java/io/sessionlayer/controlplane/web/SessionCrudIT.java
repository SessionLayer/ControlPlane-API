package io.sessionlayer.controlplane.web;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.data.runtime.AccessLockRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * Runtime SSH-session admin CRUD end to end (Design §12A): list (with identity/
 * active-only filters), get, and the teardown terminate — {@code audit:read}
 * gates reads, {@code lock:write} gates terminate, and terminate pushes an
 * identity-scoped strict {@code Lock} (reusing the S10 §8.3 deny path) +
 * audits.
 */
class SessionCrudIT extends AbstractConfigApiIT {

	@Autowired
	SshSessionRepository sessions;
	@Autowired
	AccessLockRepository accessLocks;

	// node_id/gateway_id are FKs (ON DELETE SET NULL); leaving them null keeps the
	// fixture self-contained (no node/gateway rows needed).
	private SshSession active(String identity) {
		return sessions.save(SshSession.create(identity, null, null, "deploy", null, null, "standing",
				List.of("shell", "exec"), null, null, null, null, null, null, Instant.now())).block();
	}

	private SshSession ended(String identity) {
		SshSession base = SshSession.create(identity, null, null, "deploy", null, null, "standing", List.of("shell"),
				null, null, null, null, null, null, Instant.now().minusSeconds(3600));
		return sessions.save(new SshSession(base.id(), base.identity(), null, null, base.principal(), null, null,
				base.accessModel(), base.capabilities(), null, null, null, null, null, null, base.startedAt(),
				Instant.now(), "client", null, null, null)).block();
	}

	@Test
	void listGetTerminatePushesIdentityScopedLock() {
		String admin = "svc-session-admin-" + UUID.randomUUID();
		String token = tokenWith(admin, PlatformPermissions.AUDIT_READ, PlatformPermissions.LOCK_WRITE);
		String identity = "alice-" + UUID.randomUUID() + "@corp";
		SshSession live = active(identity);
		ended(identity);

		// Filter by identity returns both this identity's sessions.
		client.get().uri("/v1/sessions?identity=" + identity).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.items.length()").isEqualTo(2);

		// activeOnly narrows to the un-ended session.
		client.get().uri("/v1/sessions?identity=" + identity + "&activeOnly=true")
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isOk().expectBody()
				.jsonPath("$.items.length()").isEqualTo(1).jsonPath("$.items[0].id").isEqualTo(live.id().toString());

		client.get().uri("/v1/sessions/" + live.id()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isOk().expectBody().jsonPath("$.identity").isEqualTo(identity).jsonPath("$.accessModel")
				.isEqualTo("standing").jsonPath("$.principal").isEqualTo("deploy");

		// Terminate → 202 + an identity-scoped strict lock + a session.terminate audit.
		client.post().uri("/v1/sessions/" + live.id() + "/terminate").header("Authorization", "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("reason", "incident-9")).exchange()
				.expectStatus().isEqualTo(202).expectBody().jsonPath("$.id").isEqualTo(live.id().toString());

		List<AccessLock> locks = accessLocks.findAll().collectList().block();
		assertThat(locks).anySatisfy(lock -> {
			assertThat(lock.mode()).isEqualTo("strict");
			assertThat(lock.targetSelector().path("identities").toString()).contains(identity);
		});
		List<AuditEvent> audit = auditEvents.findByActor(admin).collectList().block();
		assertThat(audit).anySatisfy(e -> assertThat(e.action()).isEqualTo("session.terminate"));
	}

	@Test
	void readsRequireAuditReadTerminateRequiresLockWrite() {
		String identity = "bob-" + UUID.randomUUID() + "@corp";
		SshSession live = active(identity);

		String none = "svc-session-none-" + UUID.randomUUID();
		String noneToken = tokenWith(none);
		client.get().uri("/v1/sessions").header("Authorization", "Bearer " + noneToken).exchange().expectStatus()
				.isForbidden();
		client.get().uri("/v1/sessions/" + live.id()).header("Authorization", "Bearer " + noneToken).exchange()
				.expectStatus().isForbidden();

		// audit:read admits reads but NOT terminate (that needs lock:write).
		String reader = "svc-session-reader-" + UUID.randomUUID();
		String readToken = tokenWith(reader, PlatformPermissions.AUDIT_READ);
		client.get().uri("/v1/sessions").header("Authorization", "Bearer " + readToken).exchange().expectStatus()
				.isOk();
		client.post().uri("/v1/sessions/" + live.id() + "/terminate").header("Authorization", "Bearer " + readToken)
				.contentType(MediaType.APPLICATION_JSON).bodyValue(Map.of("reason", "nope")).exchange().expectStatus()
				.isForbidden();
	}

	@Test
	void getUnknownSessionIsNotFound() {
		String token = tokenWith("svc-session-404-" + UUID.randomUUID(), PlatformPermissions.AUDIT_READ);
		client.get().uri("/v1/sessions/" + UUID.randomUUID()).header("Authorization", "Bearer " + token).exchange()
				.expectStatus().isNotFound();
	}
}
