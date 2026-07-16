package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.platform.PlatformPermissions;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Recording retention/legal-hold/governance-delete end to end (Part D,
 * FR-AUD-3/6): a governance delete by the {@code recording:delete} custodian
 * erases the encrypted object + is audited while the provenance row is
 * retained; a compliance object is un-deletable (object-lock); a legal hold
 * blocks both delete and prune; the retention job prunes past-retention
 * governance recordings.
 */
class RecordingGovernanceIT extends AbstractRecordingIT {

	@Test
	void governanceDeleteErasesObjectRetainsRowAndAudits() throws Exception {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("heidi-" + unique(), nodeId);
		String key = objectKey(sessionId);
		putObject(key, "governance", "sealed".getBytes());
		RecordingRef ref = seedRecording(sessionId, key, "governance", Instant.now().plusSeconds(86_400), false);

		String svc = "svc-rec-del-" + unique();
		String token = tokenWith(svc, PlatformPermissions.RECORDING_DELETE);
		client.method(org.springframework.http.HttpMethod.DELETE).uri("/v1/recordings/" + ref.id())
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isNoContent();

		try (S3Client admin = adminS3()) {
			assertThatThrownBy(() -> admin.headObject(b -> b.bucket(wormProperties.getBucket()).key(key)))
					.isInstanceOf(S3Exception.class);
		}
		RecordingRef after = recordings.findById(ref.id()).block();
		assertThat(after).isNotNull(); // provenance row retained (crown jewels)
		assertThat(after.prunedAt()).isNotNull();
		assertThat(after.deleteMode()).isEqualTo("governance");
		assertThat(after.deletedBy()).isEqualTo(svc);
		assertThat(auditEvents.findByActor(svc).collectList().block())
				.anySatisfy(e -> assertThat(e.action()).isEqualTo("recording.delete"));
	}

	@Test
	void governanceDeleteRequiresRecordingDeletePermission() {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("ivan-" + unique(), nodeId);
		RecordingRef ref = seedRecording(sessionId, objectKey(sessionId), "governance",
				Instant.now().plusSeconds(86_400), false);

		String replayOnly = tokenWith("svc-rec-ro-" + unique(), PlatformPermissions.RECORDING_REPLAY);
		client.method(org.springframework.http.HttpMethod.DELETE).uri("/v1/recordings/" + ref.id())
				.header("Authorization", "Bearer " + replayOnly).exchange().expectStatus().isForbidden();
	}

	@Test
	void governanceDeleteIsIdempotent() throws Exception {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("judy-" + unique(), nodeId);
		String key = objectKey(sessionId);
		putObject(key, "governance", "sealed".getBytes());
		RecordingRef ref = seedRecording(sessionId, key, "governance", Instant.now().plusSeconds(86_400), false);

		String token = tokenWith("svc-rec-idem-" + unique(), PlatformPermissions.RECORDING_DELETE);
		for (int i = 0; i < 2; i++) {
			client.method(org.springframework.http.HttpMethod.DELETE).uri("/v1/recordings/" + ref.id())
					.header("Authorization", "Bearer " + token).exchange().expectStatus().isNoContent();
		}
	}

	@Test
	void complianceRecordingCannotBeDeleted() throws Exception {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("mallory-" + unique(), nodeId);
		String key = objectKey(sessionId);
		putObject(key, "compliance", "immutable".getBytes());
		RecordingRef ref = seedRecording(sessionId, key, "compliance", Instant.now().plusSeconds(86_400), false);

		String token = tokenWith("svc-rec-comp-" + unique(), PlatformPermissions.RECORDING_DELETE);
		client.method(org.springframework.http.HttpMethod.DELETE).uri("/v1/recordings/" + ref.id())
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isEqualTo(409);

		// The API refused it; and the object-lock genuinely prevents deletion even by
		// the bucket owner (§15) — the object is still there.
		try (S3Client admin = adminS3()) {
			assertThat(admin.headObject(b -> b.bucket(wormProperties.getBucket()).key(key)).contentLength())
					.isGreaterThan(0);
			String versionId = admin.headObject(b -> b.bucket(wormProperties.getBucket()).key(key)).versionId();
			assertThatThrownBy(
					() -> admin.deleteObject(b -> b.bucket(wormProperties.getBucket()).key(key).versionId(versionId)))
					.isInstanceOf(S3Exception.class);
		}
		assertThat(recordings.findById(ref.id()).block().prunedAt()).isNull();
	}

	@Test
	void legalHeldRecordingBlocksDeleteAndPrune() throws Exception {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("niaj-" + unique(), nodeId);
		String key = objectKey(sessionId);
		putObject(key, "governance", "sealed".getBytes());
		// Past retention AND legal-held: the pruner must still skip it.
		RecordingRef ref = seedRecording(sessionId, key, "governance", Instant.now().minusSeconds(3600), true);

		String token = tokenWith("svc-rec-hold-" + unique(), PlatformPermissions.RECORDING_DELETE);
		client.method(org.springframework.http.HttpMethod.DELETE).uri("/v1/recordings/" + ref.id())
				.header("Authorization", "Bearer " + token).exchange().expectStatus().isEqualTo(409);

		retention.prune("test").block();

		try (S3Client admin = adminS3()) {
			assertThat(admin.headObject(b -> b.bucket(wormProperties.getBucket()).key(key)).contentLength())
					.isGreaterThan(0);
		}
		assertThat(recordings.findById(ref.id()).block().prunedAt()).isNull();
	}

	@Test
	void legalHoldSetAndReleaseIsAuditedAndIdempotent() {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("olivia-" + unique(), nodeId);
		RecordingRef ref = seedRecording(sessionId, objectKey(sessionId), "governance",
				Instant.now().plusSeconds(86_400), false);

		String svc = "svc-rec-lh-" + unique();
		String token = tokenWith(svc, PlatformPermissions.RECORDING_DELETE);

		client.put().uri("/v1/recordings/" + ref.id() + "/legal-hold").header("Authorization", "Bearer " + token)
				.bodyValue(Map.of("held", true, "reason", "litigation")).exchange().expectStatus().isOk().expectBody()
				.jsonPath("$.legalHold").isEqualTo(true);
		// Idempotent by desired state: a second held=true does not re-audit.
		client.put().uri("/v1/recordings/" + ref.id() + "/legal-hold").header("Authorization", "Bearer " + token)
				.bodyValue(Map.of("held", true)).exchange().expectStatus().isOk();
		client.put().uri("/v1/recordings/" + ref.id() + "/legal-hold").header("Authorization", "Bearer " + token)
				.bodyValue(Map.of("held", false)).exchange().expectStatus().isOk().expectBody().jsonPath("$.legalHold")
				.isEqualTo(false);

		List<AuditEvent> holds = auditEvents.findByActor(svc).collectList().block().stream()
				.filter(e -> e.action().equals("recording.legal_hold")).toList();
		assertThat(holds).hasSize(2); // place + release only (the redundant place is a no-op)
		assertThat(recordings.findById(ref.id()).block().legalHold()).isFalse();
	}

	@Test
	void retentionJobPrunesPastRetentionGovernanceRecording() throws Exception {
		UUID nodeId = seedNode(Map.of("env", "prod"));
		UUID sessionId = seedSession("peggy-" + unique(), nodeId);
		String key = objectKey(sessionId);
		putObject(key, "governance", "sealed".getBytes());
		RecordingRef ref = seedRecording(sessionId, key, "governance", Instant.now().minusSeconds(3600), false);

		retention.prune("test").block();

		try (S3Client admin = adminS3()) {
			assertThatThrownBy(() -> admin.headObject(b -> b.bucket(wormProperties.getBucket()).key(key)))
					.isInstanceOf(S3Exception.class);
		}
		RecordingRef after = recordings.findById(ref.id()).block();
		assertThat(after.prunedAt()).isNotNull();
		assertThat(after.deleteMode()).isEqualTo("retention");
		assertThat(after.deletedBy()).isNull();
		assertThat(auditEvents.findBySessionId(sessionId).collectList().block())
				.anySatisfy(e -> assertThat(e.action()).isEqualTo("recording.prune"));
	}
}
