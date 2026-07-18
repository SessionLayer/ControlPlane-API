package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.netty.handler.ssl.SslContext;
import io.sessionlayer.controlplane.data.config.DpRule;
import io.sessionlayer.controlplane.data.config.DpRuleRepository;
import io.sessionlayer.controlplane.data.config.OperatorSettings;
import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingToken;
import io.sessionlayer.controlplane.data.runtime.RecordingTokenRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.gateway.SingleUseTokens;
import io.sessionlayer.controlplane.grpc.v1.AuthorizationGrpc;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeRequest;
import io.sessionlayer.controlplane.grpc.v1.AuthorizeResponse;
import io.sessionlayer.controlplane.grpc.v1.BeginRecordingRequest;
import io.sessionlayer.controlplane.grpc.v1.BeginRecordingResponse;
import io.sessionlayer.controlplane.grpc.v1.Decision;
import io.sessionlayer.controlplane.grpc.v1.FileTransferAudit;
import io.sessionlayer.controlplane.grpc.v1.FinalizeRecordingRequest;
import io.sessionlayer.controlplane.grpc.v1.FinalizeRecordingResponse;
import io.sessionlayer.controlplane.grpc.v1.KeySealAlgorithm;
import io.sessionlayer.controlplane.grpc.v1.RecordingGrpc;
import io.sessionlayer.controlplane.grpc.v1.RecordingStatus;
import io.sessionlayer.controlplane.grpc.v1.RequestUploadRequest;
import io.sessionlayer.controlplane.grpc.v1.UploadCredential;
import io.sessionlayer.controlplane.grpc.v1.WormMode;
import io.sessionlayer.controlplane.recording.RecordingStore.PresignedAccess;
import io.sessionlayer.controlplane.recording.WormObjectStore;
import io.sessionlayer.controlplane.recording.WormProperties;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.ObjectLockRetentionMode;
import software.amazon.awssdk.services.s3.model.S3Exception;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Session Nine end-to-end: the {@code Recording} gRPC service over mTLS against
 * a real Postgres + MinIO WORM store (Design §12/§15; FR-AUD-1/2/3/9,
 * FR-DATA-2). Proves the Begin → RequestUpload → PUT → Finalize lifecycle:
 * {@code Authorize} ALLOW mints a recording token; {@code BeginRecording}
 * registers the 1:1 {@code recording_ref} + returns the customer key (no upload
 * cred); {@code
 * RequestUpload} issues a fresh short-lived presigned PUT at upload time that
 * lands the object; replayed / cross-gateway / expired tokens + invalid
 * customer keys fail closed; {@code FinalizeRecording} commits integrity + the
 * (validated) SFTP audit correlated into the one stream; and a WORM object-lock
 * cannot be stripped or deleted.
 */
class RecordingIT extends AbstractMtlsIT {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;
	private static final String BUCKET = "recordings-" + UUID.randomUUID().toString().substring(0, 8);

	@SuppressWarnings("resource") // shared singleton; stopped by Ryuk at JVM exit
	static final GenericContainer<?> MINIO = new GenericContainer<>(
			DockerImageName.parse("minio/minio:RELEASE.2025-04-08T15-41-24Z")).withCommand("server", "/data")
			.withEnv("MINIO_ROOT_USER", "sessionlayer").withEnv("MINIO_ROOT_PASSWORD", "sessionlayer-dev-secret")
			.withExposedPorts(9000).waitingFor(Wait.forHttp("/minio/health/live").forPort(9000).forStatusCode(200));

	static {
		MINIO.start();
	}

	@org.springframework.test.context.DynamicPropertySource
	static void worm(org.springframework.test.context.DynamicPropertyRegistry registry) {
		registry.add("sessionlayer.recording.worm.endpoint",
				() -> "http://" + MINIO.getHost() + ":" + MINIO.getMappedPort(9000));
		registry.add("sessionlayer.recording.worm.bucket", () -> BUCKET);
		registry.add("sessionlayer.recording.worm.region", () -> "us-east-1");
		registry.add("sessionlayer.recording.worm.access-key", () -> "sessionlayer");
		registry.add("sessionlayer.recording.worm.secret-key", () -> "sessionlayer-dev-secret");
		registry.add("sessionlayer.recording.worm.path-style-access", () -> "true");
	}

	@Autowired
	private NodeRepository nodes;
	@Autowired
	private DpRuleRepository dpRules;
	@Autowired
	private OperatorSettingsRepository operatorSettings;
	@Autowired
	private RecordingRefRepository recordings;
	@Autowired
	private RecordingTokenRepository recordingTokens;
	@Autowired
	private SshSessionRepository sshSessions;
	@Autowired
	private AuditEventRepository audits;
	@Autowired
	private WormProperties wormProperties;
	@Autowired
	private WormObjectStore worm;

	@Test
	void beginThenRequestUploadLandsTheObject() throws Exception {
		byte[] customerKey = configureCustomerKey("kms://customer-1", "governance");
		String identity = "alice-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell", "exec"));
		EnrolledGateway gateway = enroll("gw-rec-" + unique());
		UUID sessionId = UUID.randomUUID();

		AuthorizeResponse authz = authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", sessionId);
		assertThat(authz.getDecision()).isEqualTo(Decision.DECISION_ALLOW);
		assertThat(authz.getRecordingToken()).isNotBlank();
		assertThat(authz.getRecordingToken()).isNotEqualTo(authz.getSessionToken());

		BeginRecordingResponse begin = beginRecording(gateway, authz.getRecordingToken());
		assertThat(begin.getRecordingId()).isNotBlank();
		assertThat(begin.getObjectKey())
				.isEqualTo("recordings/" + sessionId + "/" + begin.getRecordingId() + ".cast.enc");
		// worm mode is the operator default (governance) here
		assertThat(begin.getWormMode()).isEqualTo(WormMode.WORM_MODE_GOVERNANCE);
		assertThat(begin.getCustomerKey().getAlgorithm())
				.isEqualTo(KeySealAlgorithm.KEY_SEAL_ALGORITHM_ECIES_P256_HKDF_SHA256_AES256GCM);
		assertThat(begin.getCustomerKey().getPublicKey().toByteArray()).isEqualTo(customerKey);
		assertThat(begin.getCustomerKey().getKeyRef()).isEqualTo("kms://customer-1");

		// recording_ref written 1:1 with the session (FR-DATA-2).
		RecordingRef ref = recordings.findBySessionId(sessionId).block();
		assertThat(ref).isNotNull();
		assertThat(ref.objectKey()).isEqualTo(begin.getObjectKey());
		assertThat(ref.encryptionKeyRef()).isEqualTo("kms://customer-1");
		assertThat(ref.status()).isEqualTo("recording");
		assertThat(ref.wormMode()).isEqualTo("governance");
		assertThat(ref.retentionUntil()).isAfter(Instant.now());

		// The upload credential is issued at upload time (RequestUpload), short-lived.
		UploadCredential upload = requestUpload(gateway, begin.getRecordingId());
		assertThat(upload.getMethod()).isEqualTo("PUT");
		assertThat(upload.getUrl()).startsWith("http");
		assertThat(upload.getRequiredHeadersMap()).isNotEmpty();
		assertThat(upload.getExpiresAtEpochSeconds()).isGreaterThan(Instant.now().getEpochSecond());

		byte[] ciphertext = "sealed-asciicast-bytes".getBytes();
		assertThat(put(upload, ciphertext)).isEqualTo(200);
		try (S3Client admin = adminS3()) {
			long len = admin.headObject(b -> b.bucket(BUCKET).key(begin.getObjectKey())).contentLength();
			assertThat(len).isEqualTo(ciphertext.length);
		}
	}

	@Test
	void requestUploadIssuesAFreshCredentialAtUploadTime() throws Exception {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "ivan-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-upload-" + unique());
		AuthorizeResponse authz = authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID());
		BeginRecordingResponse begin = beginRecording(gateway, authz.getRecordingToken());

		// The credential lifetime is the UPLOAD, not the session: a later RequestUpload
		// issues a freshly-dated credential (so a long session never carries a stale
		// begin-time cred). Not single-use — it can be re-requested.
		UploadCredential first = requestUpload(gateway, begin.getRecordingId());
		Thread.sleep(2000);
		UploadCredential second = requestUpload(gateway, begin.getRecordingId());
		assertThat(second.getExpiresAtEpochSeconds()).isGreaterThanOrEqualTo(first.getExpiresAtEpochSeconds());
		assertThat(second.getExpiresAtEpochSeconds()).isGreaterThan(Instant.now().getEpochSecond());
		assertThat(put(second, "bytes".getBytes())).isEqualTo(200);
	}

	@Test
	void requestUploadByANonOwnerGatewayIsRejected() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "heidi-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		EnrolledGateway owner = enroll("gw-up-owner-" + unique());
		EnrolledGateway other = enroll("gw-up-other-" + unique());
		AuthorizeResponse authz = authorize(owner, identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID());
		BeginRecordingResponse begin = beginRecording(owner, authz.getRecordingToken());

		assertThatThrownBy(() -> requestUpload(other, begin.getRecordingId()))
				.isInstanceOf(StatusRuntimeException.class)
				.satisfies(e -> assertThat(((StatusRuntimeException) e).getStatus().getCode())
						.isEqualTo(io.grpc.Status.Code.PERMISSION_DENIED));
	}

	@Test
	void replayedRecordingTokenIsRejected() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "bob-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-replay-" + unique());
		AuthorizeResponse authz = authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID());

		beginRecording(gateway, authz.getRecordingToken()); // first use consumes it
		assertThatThrownBy(() -> beginRecording(gateway, authz.getRecordingToken()))
				.isInstanceOf(StatusRuntimeException.class)
				.satisfies(e -> assertThat(((StatusRuntimeException) e).getStatus().getCode())
						.isEqualTo(io.grpc.Status.Code.PERMISSION_DENIED));
	}

	@Test
	void crossGatewayRecordingTokenIsRejected() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "carol-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		EnrolledGateway broker = enroll("gw-broker-" + unique());
		EnrolledGateway thief = enroll("gw-thief-" + unique());
		AuthorizeResponse authz = authorize(broker, identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID());

		assertThatThrownBy(() -> beginRecording(thief, authz.getRecordingToken()))
				.isInstanceOf(StatusRuntimeException.class)
				.satisfies(e -> assertThat(((StatusRuntimeException) e).getStatus().getCode())
						.isEqualTo(io.grpc.Status.Code.PERMISSION_DENIED));
	}

	@Test
	void expiredRecordingTokenIsRejected() {
		configureCustomerKey("kms://customer-1", "governance");
		EnrolledGateway gateway = enroll("gw-expired-" + unique());
		// Seed an already-expired token bound to this gateway (hash stored; raw known).
		String raw = "raw-" + UUID.randomUUID();
		recordingTokens.save(RecordingToken.create(SingleUseTokens.hash(raw), gateway.gatewayId(), UUID.randomUUID(),
				UUID.randomUUID(), "deploy", "10.0.0.5", Instant.now().minusSeconds(60))).block();

		assertThatThrownBy(() -> beginRecording(gateway, raw)).isInstanceOf(StatusRuntimeException.class)
				.satisfies(e -> assertThat(((StatusRuntimeException) e).getStatus().getCode())
						.isEqualTo(io.grpc.Status.Code.PERMISSION_DENIED));
	}

	@Test
	void noCustomerKeyConfiguredFailsClosed() {
		clearCustomerKey();
		EnrolledGateway gateway = enroll("gw-nokey-" + unique());
		AuthorizeResponse authz = authorizeFresh(gateway);
		assertBeginFailsClosed(gateway, authz.getRecordingToken());
	}

	@Test
	void invalidCustomerKeyFailsClosed() {
		// A blob that is not a valid SPKI public key (garbage / a private key) must be
		// refused rather than handed to the Gateway to seal a recording to (§15).
		writeSettings("not-a-public-key".getBytes(), "kms://bad", "governance");
		EnrolledGateway gateway = enroll("gw-badkey-" + unique());
		AuthorizeResponse authz = authorizeFresh(gateway);
		assertBeginFailsClosed(gateway, authz.getRecordingToken());
	}

	@Test
	void finalizeCommitsIntegrityAndCorrelatesSftpAudit() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "erin-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell", "sftp"));
		EnrolledGateway gateway = enroll("gw-final-" + unique());
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse authz = authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", sessionId);
		BeginRecordingResponse begin = beginRecording(gateway, authz.getRecordingToken());

		String head = "sha256:" + "a".repeat(64);
		String digest = "sha256:" + "b".repeat(64);
		FinalizeRecordingRequest finalize = FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setHashChainHead(head).setContentDigest(digest)
				.setByteLen(4096)
				.addSftpAudit(FileTransferAudit.newBuilder().setOperation("write").setPath("/etc/app.conf")
						.setDirection("upload").setSize(128).setSha256("sha256:" + "c".repeat(64)).build())
				.build();
		FinalizeRecordingResponse response = finalizeRecording(gateway, finalize);
		assertThat(response.getStatus()).isEqualTo(RecordingStatus.RECORDING_STATUS_FINALIZED);

		RecordingRef ref = recordings.findBySessionId(sessionId).block();
		assertThat(ref.status()).isEqualTo("finalized");
		assertThat(ref.hashChainHead()).isEqualTo(head);
		assertThat(ref.contentDigest()).isEqualTo(digest);
		assertThat(ref.sizeBytes()).isEqualTo(4096L);

		// FR-AUD-9: begin, sftp.write and finalize share the one correlated stream by
		// session id.
		List<AuditEvent> events = audits.findBySessionId(sessionId).collectList().block();
		List<String> actions = events.stream().map(AuditEvent::action).toList();
		assertThat(actions).contains("recording.begin", "sftp.write", "recording.finalize");
		AuditEvent sftp = events.stream().filter(e -> e.action().equals("sftp.write")).findFirst().orElseThrow();
		assertThat(sftp.detail().get("path").asString()).isEqualTo("/etc/app.conf");
		assertThat(sftp.detail().get("direction").asString()).isEqualTo("upload");
	}

	// FR-SESS-3 lifecycle completion: the first terminal finalize closes the owning
	// session (ended_at + a status-derived end_reason), freeing the identity's
	// concurrency slot and filling the history the SessionController exposes. The
	// close is idempotent — a same-status re-finalize does not move the end stamp.
	@Test
	void finalizeMarksTheOwningSessionEndedWithADerivedReason() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "victor-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-endreason-" + unique());
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse authz = authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", sessionId);
		BeginRecordingResponse begin = beginRecording(gateway, authz.getRecordingToken());

		// Live before finalize (no end stamp).
		assertThat(sshSessions.findById(sessionId).block().endedAt()).isNull();

		finalizeRecording(gateway, FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setByteLen(1).build());

		SshSession ended = sshSessions.findById(sessionId).block();
		assertThat(ended.endedAt()).isNotNull();
		assertThat(ended.endReason()).isEqualTo("closed"); // finalized → clean close

		// A same-status re-finalize is a no-op that does not move the end stamp.
		Instant firstEnd = ended.endedAt();
		finalizeRecording(gateway, FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setByteLen(1).build());
		assertThat(sshSessions.findById(sessionId).block().endedAt()).isEqualTo(firstEnd);
	}

	// F-recording-worm-version-1 (HIGH): FinalizeRecording carries the object-store
	// version id the Gateway PUT; the CP stores it write-once so replay/export can
	// pin
	// it. A re-finalize cannot repoint it (a compromised actor can't move the pin).
	@Test
	void finalizePersistsTheObjectVersionIdAndCannotRepointIt() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "peggy-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-ver-" + unique());
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse authz = authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", sessionId);
		BeginRecordingResponse begin = beginRecording(gateway, authz.getRecordingToken());

		finalizeRecording(gateway, FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setHashChainHead("sha256:" + "a".repeat(64))
				.setContentDigest("sha256:" + "b".repeat(64)).setByteLen(1).setObjectVersionId("ver-abc-123").build());
		RecordingRef ref = recordings.findBySessionId(sessionId).block();
		assertThat(ref.objectVersionId()).isEqualTo("ver-abc-123");

		// A same-status re-finalize with an EVIL version id is an idempotent no-op —
		// the
		// pinned version does not move (belt; the DB write-once trigger is the
		// suspenders).
		finalizeRecording(gateway, FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setObjectVersionId("ver-EVIL-999").build());
		assertThat(recordings.findBySessionId(sessionId).block().objectVersionId()).isEqualTo("ver-abc-123");
	}

	// F-recording-worm-version-1 (F4): a finalized recording is terminal —
	// RequestUpload
	// is refused so a compromised/buggy Gateway can't shadow the WORM-locked object
	// with
	// a later version to the same key (§15 crown-jewels).
	@Test
	void requestUploadAfterFinalizeIsRefused() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "trent-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		EnrolledGateway gateway = enroll("gw-final-noupload-" + unique());
		AuthorizeResponse authz = authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID());
		BeginRecordingResponse begin = beginRecording(gateway, authz.getRecordingToken());
		finalizeRecording(gateway, FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setHashChainHead("sha256:" + "a".repeat(64))
				.setContentDigest("sha256:" + "b".repeat(64)).setByteLen(1).build());

		assertThatThrownBy(() -> requestUpload(gateway, begin.getRecordingId()))
				.isInstanceOf(StatusRuntimeException.class)
				.satisfies(e -> assertThat(((StatusRuntimeException) e).getStatus().getCode())
						.isEqualTo(io.grpc.Status.Code.PERMISSION_DENIED));
	}

	@Test
	void hostileSftpMetadataIsNormalized() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "judy-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("sftp"));
		EnrolledGateway gateway = enroll("gw-hostile-" + unique());
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse authz = authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", sessionId);
		BeginRecordingResponse begin = beginRecording(gateway, authz.getRecordingToken());

		String longPath = "/" + "a".repeat(9000);
		FinalizeRecordingRequest finalize = FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setByteLen(1)
				.addSftpAudit(FileTransferAudit.newBuilder().setOperation("rm -rf /; DROP TABLE").setPath(longPath)
						.setDirection("sideways").setSize(-5).setSha256("not-a-hash").build())
				.build();
		finalizeRecording(gateway, finalize);

		AuditEvent sftp = audits.findBySessionId(sessionId).collectList().block().stream()
				.filter(e -> e.action().startsWith("sftp.")).findFirst().orElseThrow();
		// Operation allowlisted → unknown; direction constrained; bad sha256 dropped;
		// path length-bounded; negative size clamped.
		assertThat(sftp.action()).isEqualTo("sftp.unknown");
		assertThat(sftp.detail().get("direction").asString()).isEqualTo("unknown");
		assertThat(sftp.detail().has("sha256")).isFalse();
		assertThat(sftp.detail().get("path").asString().length()).isLessThanOrEqualTo(4096);
		assertThat(sftp.detail().get("size").asString()).isEqualTo("0");
	}

	@Test
	void refinalizeIsIdempotentNoOpButRejectsRelabel() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "grace-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell", "sftp"));
		EnrolledGateway gateway = enroll("gw-refinal-" + unique());
		UUID sessionId = UUID.randomUUID();
		AuthorizeResponse authz = authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", sessionId);
		BeginRecordingResponse begin = beginRecording(gateway, authz.getRecordingToken());

		String head = "sha256:" + "d".repeat(64);
		FinalizeRecordingRequest first = FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setHashChainHead(head).setByteLen(10)
				.addSftpAudit(FileTransferAudit.newBuilder().setOperation("write").setPath("/a").setDirection("upload")
						.setSize(1).build())
				.build();
		assertThat(finalizeRecording(gateway, first).getStatus()).isEqualTo(RecordingStatus.RECORDING_STATUS_FINALIZED);
		long afterFirst = audits.findBySessionId(sessionId).count().block();

		// A same-status re-finalize — even with DIFFERENT sftp_audit — is a no-op that
		// appends NOTHING (no duplicate audit rows).
		FinalizeRecordingRequest replay = FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setHashChainHead(head).setByteLen(10)
				.addSftpAudit(FileTransferAudit.newBuilder().setOperation("read").setPath("/b").setDirection("download")
						.setSize(2).build())
				.build();
		assertThat(finalizeRecording(gateway, replay).getStatus())
				.isEqualTo(RecordingStatus.RECORDING_STATUS_FINALIZED);
		assertThat(audits.findBySessionId(sessionId).count().block()).isEqualTo(afterFirst);

		// Relabeling a finalized recording to FAILED (to hide it) is refused.
		FinalizeRecordingRequest relabel = FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FAILED).setByteLen(0).build();
		assertThatThrownBy(() -> finalizeRecording(gateway, relabel)).isInstanceOf(StatusRuntimeException.class)
				.satisfies(e -> assertThat(((StatusRuntimeException) e).getStatus().getCode())
						.isEqualTo(io.grpc.Status.Code.FAILED_PRECONDITION));
	}

	@Test
	void finalizeByANonOwnerGatewayIsRejected() {
		configureCustomerKey("kms://customer-1", "governance");
		String identity = "frank-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		EnrolledGateway owner = enroll("gw-owner-" + unique());
		EnrolledGateway other = enroll("gw-other-" + unique());
		AuthorizeResponse authz = authorize(owner, identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID());
		BeginRecordingResponse begin = beginRecording(owner, authz.getRecordingToken());

		FinalizeRecordingRequest req = FinalizeRecordingRequest.newBuilder().setRecordingId(begin.getRecordingId())
				.setStatus(RecordingStatus.RECORDING_STATUS_FINALIZED).setByteLen(1).build();
		assertThatThrownBy(() -> finalizeRecording(other, req)).isInstanceOf(StatusRuntimeException.class)
				.satisfies(e -> assertThat(((StatusRuntimeException) e).getStatus().getCode())
						.isEqualTo(io.grpc.Status.Code.PERMISSION_DENIED));
	}

	@Test
	void complianceWormObjectCannotBeDeleted() throws Exception {
		String objectKey = "recordings/wormtest/" + UUID.randomUUID() + ".cast.enc";
		Instant retainUntil = Instant.now().plus(Duration.ofDays(1));
		PresignedAccess upload = worm.ensureReady().then(worm.presignUpload(objectKey, "compliance", retainUntil))
				.block();
		// The object-lock headers are part of the signature — surfaced so the uploader
		// replays them verbatim (the lock cannot be stripped).
		assertThat(upload.requiredHeaders().keySet().stream().map(String::toLowerCase))
				.anyMatch(h -> h.contains("object-lock-mode"));

		assertThat(putPresigned(upload, "immutable".getBytes())).isEqualTo(200);

		try (S3Client admin = adminS3()) {
			var retention = admin.getObjectRetention(b -> b.bucket(BUCKET).key(objectKey)).retention();
			assertThat(retention.mode()).isEqualTo(ObjectLockRetentionMode.COMPLIANCE);
			assertThat(retention.retainUntilDate()).isAfter(Instant.now());
			String versionId = admin.headObject(b -> b.bucket(BUCKET).key(objectKey)).versionId();
			// A compliance-locked version cannot be deleted before retain-until, even by
			// the bucket owner (§15: a compromised admin can't alter a recording).
			assertThatThrownBy(() -> admin.deleteObject(b -> b.bucket(BUCKET).key(objectKey).versionId(versionId)))
					.isInstanceOf(S3Exception.class);
		}
	}

	// ----------------------- helpers -----------------------

	private AuthorizeResponse authorize(EnrolledGateway gateway, String identity, UUID nodeId, String principal,
			String sourceIp, UUID sessionId) {
		AuthorizeRequest request = AuthorizeRequest.newBuilder().setIdentity(identity).setNodeId(nodeId.toString())
				.setRequestedPrincipal(principal).setSourceIp(sourceIp).setSessionId(sessionId.toString()).build();
		return onChannel(gateway, channel -> AuthorizationGrpc.newBlockingStub(channel).authorize(request));
	}

	// A minimal allow just to obtain a recording token for the fail-closed begin
	// tests.
	private AuthorizeResponse authorizeFresh(EnrolledGateway gateway) {
		String identity = "user-" + unique();
		UUID nodeId = seedProdNode();
		seedAllow(identity, List.of("deploy"), List.of("shell"));
		return authorize(gateway, identity, nodeId, "deploy", "10.0.0.5", UUID.randomUUID());
	}

	private void assertBeginFailsClosed(EnrolledGateway gateway, String recordingToken) {
		assertThatThrownBy(() -> beginRecording(gateway, recordingToken)).isInstanceOf(StatusRuntimeException.class)
				.satisfies(e -> assertThat(((StatusRuntimeException) e).getStatus().getCode())
						.isEqualTo(io.grpc.Status.Code.FAILED_PRECONDITION));
	}

	private BeginRecordingResponse beginRecording(EnrolledGateway gateway, String recordingToken) {
		BeginRecordingRequest request = BeginRecordingRequest.newBuilder().setRecordingToken(recordingToken).build();
		return onChannel(gateway, channel -> RecordingGrpc.newBlockingStub(channel).beginRecording(request));
	}

	private UploadCredential requestUpload(EnrolledGateway gateway, String recordingId) {
		RequestUploadRequest request = RequestUploadRequest.newBuilder().setRecordingId(recordingId).build();
		return onChannel(gateway, channel -> RecordingGrpc.newBlockingStub(channel).requestUpload(request)).getUpload();
	}

	private FinalizeRecordingResponse finalizeRecording(EnrolledGateway gateway, FinalizeRecordingRequest request) {
		return onChannel(gateway, channel -> RecordingGrpc.newBlockingStub(channel).finalizeRecording(request));
	}

	private <T> T onChannel(EnrolledGateway gateway, java.util.function.Function<ManagedChannel, T> call) {
		SslContext ssl = MtlsTestSupport.clientSslContext(caCertificate(), gateway.certificate(),
				gateway.keyPair().getPrivate());
		ManagedChannel channel = MtlsTestSupport.channel(grpcPort(), ssl);
		try {
			return call.apply(channel);
		} finally {
			shutdown(channel);
		}
	}

	private int put(UploadCredential upload, byte[] body) throws Exception {
		HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(upload.getUrl())).method(upload.getMethod(),
				HttpRequest.BodyPublishers.ofByteArray(body));
		upload.getRequiredHeadersMap().forEach((name, value) -> {
			if (!isRestricted(name)) {
				request.header(name, value);
			}
		});
		return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
	}

	private int putPresigned(PresignedAccess upload, byte[] body) throws Exception {
		HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(upload.url())).method(upload.method(),
				HttpRequest.BodyPublishers.ofByteArray(body));
		upload.requiredHeaders().forEach((name, value) -> {
			if (!isRestricted(name)) {
				request.header(name, value);
			}
		});
		return HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
	}

	// The JDK HttpClient manages host/content-length itself (they are restricted);
	// the
	// signed host equals the URL host, so letting the client set it keeps the
	// signature.
	private static boolean isRestricted(String header) {
		return header.equalsIgnoreCase("host") || header.equalsIgnoreCase("content-length");
	}

	private S3Client adminS3() {
		return S3Client.builder().region(Region.of(wormProperties.getRegion()))
				.endpointOverride(URI.create(wormProperties.getEndpoint()))
				.credentialsProvider(StaticCredentialsProvider.create(
						AwsBasicCredentials.create(wormProperties.getAccessKey(), wormProperties.getSecretKey())))
				.serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build()).build();
	}

	private byte[] configureCustomerKey(String keyRef, String wormMode) {
		byte[] der = MtlsTestSupport.generateEcKeyPair().getPublic().getEncoded(); // DER SubjectPublicKeyInfo
		writeSettings(der, keyRef, wormMode);
		return der;
	}

	private void clearCustomerKey() {
		writeSettings(null, null, "governance");
	}

	private void writeSettings(byte[] publicKey, String keyRef, String wormMode) {
		OperatorSettings base = operatorSettings.findSingleton()
				.switchIfEmpty(operatorSettings.save(OperatorSettings.defaults())).block();
		OperatorSettings updated = new OperatorSettings(base.id(), base.singleton(), base.kekReference(),
				base.defaultCaBackend(), base.auditRetentionDays(), wormMode, base.otpTtlSeconds(),
				base.defaultMaxSessionSeconds(), base.defaultIdleTimeoutSeconds(), base.defaultMaxConcurrentSessions(),
				base.bootstrapAdminSubject(), base.bootstrapCredentialHash(), base.bootstrapCompleted(),
				base.bootstrapCompletedAt(), publicKey, "ecies_p256", keyRef, 365, true, base.origin(), base.version(),
				base.createdAt(), base.updatedAt());
		operatorSettings.save(updated).block();
	}

	private UUID seedProdNode() {
		ObjectNode labels = JSON.objectNode().put("env", "prod");
		return nodes.save(Node.create("node-" + unique(), null, labels, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	private void seedAllow(String identity, List<String> principals, List<String> capabilities) {
		ObjectNode identitySelector = JSON.objectNode();
		identitySelector.set("identities", JSON.arrayNode().add(identity));
		ObjectNode labelSelector = JSON.objectNode();
		labelSelector.set("env", JSON.objectNode().put("op", "eq").put("value", "prod"));
		dpRules.save(DpRule.create("rule-" + unique(), identitySelector, labelSelector, null, principals, 3600,
				capabilities, "allow", "api")).block();
	}

	private static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
