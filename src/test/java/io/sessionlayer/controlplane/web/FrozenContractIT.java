package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.platform.PlatformPermissions;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

/**
 * The Part C frozen surface (recordings + audit-events, Design §12.2): the
 * routes exist in the contract but are unimplemented until Session 18. Each is
 * RBAC-gated, so with the right permission it returns a {@code 501} not-
 * implemented problem, and without it a generic {@code 403} — never a leaky
 * stub.
 */
class FrozenContractIT extends AbstractConfigApiIT {

	private static final String NOT_IMPLEMENTED = "https://docs.sessionlayer.example/problems/not-implemented";

	@Test
	void recordingRoutesAreFrozenForAuthorizedAndForbiddenForUnauthorized() {
		String replay = tokenWith("svc-rec-replay-" + UUID.randomUUID(), PlatformPermissions.RECORDING_REPLAY);
		String export = tokenWith("svc-rec-export-" + UUID.randomUUID(), PlatformPermissions.RECORDING_EXPORT);
		String none = tokenWith("svc-rec-none-" + UUID.randomUUID());
		UUID id = UUID.randomUUID();

		frozen(HttpMethod.GET, "/v1/recordings", replay);
		frozen(HttpMethod.GET, "/v1/recordings/" + id, replay);
		frozen(HttpMethod.POST, "/v1/recordings/" + id + "/replay", replay);
		frozen(HttpMethod.POST, "/v1/recordings/" + id + "/export", export);

		forbidden(HttpMethod.GET, "/v1/recordings", none);
		forbidden(HttpMethod.GET, "/v1/recordings/" + id, none);
		forbidden(HttpMethod.POST, "/v1/recordings/" + id + "/replay", none);
		forbidden(HttpMethod.POST, "/v1/recordings/" + id + "/export", none);
		// recording:replay does not grant export.
		forbidden(HttpMethod.POST, "/v1/recordings/" + id + "/export", replay);
	}

	@Test
	void auditEventRoutesAreFrozenForAuthorizedAndForbiddenForUnauthorized() {
		String read = tokenWith("svc-audit-read-" + UUID.randomUUID(), PlatformPermissions.AUDIT_READ);
		String none = tokenWith("svc-audit-none-" + UUID.randomUUID());
		UUID id = UUID.randomUUID();

		frozen(HttpMethod.GET, "/v1/audit-events", read);
		frozen(HttpMethod.GET, "/v1/audit-events/" + id, read);

		forbidden(HttpMethod.GET, "/v1/audit-events", none);
		forbidden(HttpMethod.GET, "/v1/audit-events/" + id, none);
	}

	private void frozen(HttpMethod method, String uri, String token) {
		client.method(method).uri(uri).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isEqualTo(501).expectBody().jsonPath("$.type").isEqualTo(NOT_IMPLEMENTED);
	}

	private void forbidden(HttpMethod method, String uri, String token) {
		client.method(method).uri(uri).header("Authorization", "Bearer " + token).exchange().expectStatus()
				.isForbidden();
	}
}
