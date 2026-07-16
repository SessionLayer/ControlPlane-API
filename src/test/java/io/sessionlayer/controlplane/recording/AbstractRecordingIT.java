package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.data.config.PlatformRole;
import io.sessionlayer.controlplane.data.config.PlatformRoleRepository;
import io.sessionlayer.controlplane.data.config.RoleBinding;
import io.sessionlayer.controlplane.data.config.RoleBindingRepository;
import io.sessionlayer.controlplane.data.config.ServiceAccount;
import io.sessionlayer.controlplane.data.config.ServiceAccountRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import io.sessionlayer.controlplane.data.runtime.RecordingRef;
import io.sessionlayer.controlplane.data.runtime.RecordingRefRepository;
import io.sessionlayer.controlplane.data.runtime.SshSession;
import io.sessionlayer.controlplane.data.runtime.SshSessionRepository;
import io.sessionlayer.controlplane.machine.MachineIdentityService;
import io.sessionlayer.controlplane.support.AbstractConfigApiIT;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Base for the S18 recording read/lifecycle ITs: the
 * {@link AbstractConfigApiIT} auth + WebTestClient harness backed by a real
 * MinIO WORM store (the read side of the S9 write path). Provides
 * recording/session/node seeding, a scoped platform-role token minter (for
 * FR-PADM-2 scope tests), and per-test cleanup of the rows it creates.
 */
public abstract class AbstractRecordingIT extends AbstractConfigApiIT {

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
	protected SshSessionRepository sessions;
	@Autowired
	protected RecordingRefRepository recordings;
	@Autowired
	protected NodeRepository nodes;
	@Autowired
	protected WormObjectStore worm;
	@Autowired
	protected WormProperties wormProperties;
	@Autowired
	protected RecordingRetentionService retention;
	@Autowired
	protected ObjectMapper json;
	@Autowired
	private ServiceAccountRepository serviceAccounts;
	@Autowired
	private PlatformRoleRepository roles;
	@Autowired
	private RoleBindingRepository bindings;
	@Autowired
	private MachineIdentityService machineIdentity;

	private final List<UUID> createdSessions = new ArrayList<>();

	@AfterEach
	void cleanRecordingRows() {
		// recording_ref → ssh_session is ON DELETE RESTRICT, so recordings first. Only
		// this IT writes recording_ref in the shared container; sessions are removed by
		// id so a sibling suite's rows are left untouched.
		recordings.deleteAll().block();
		for (UUID sessionId : createdSessions) {
			sessions.deleteById(sessionId).onErrorComplete().block();
		}
		createdSessions.clear();
	}

	protected UUID seedNode(Map<String, String> labels) {
		ObjectNode labelNode = json.createObjectNode();
		labels.forEach(labelNode::put);
		return nodes.save(Node.create("node-" + unique(), null, labelNode, "agent", "active", "healthy", null, null))
				.map(Node::id).block();
	}

	protected UUID seedSession(String identity, UUID nodeId) {
		SshSession saved = sessions.save(SshSession.create(identity, nodeId, "node-" + unique(), "deploy", null, null,
				"standing", List.of("shell", "exec"), null, null, null, null, null, null, Instant.now())).block();
		createdSessions.add(saved.id());
		return saved.id();
	}

	protected RecordingRef seedRecording(UUID sessionId, String objectKey, String wormMode, Instant retentionUntil,
			boolean legalHold) {
		RecordingRef ref = RecordingRef.begin(UUID.randomUUID(), sessionId, objectKey, "kms://customer-1", wormMode,
				retentionUntil);
		if (legalHold) {
			ref = ref.withLegalHold(true, "litigation");
		}
		return recordings.save(ref).block();
	}

	protected String objectKey(UUID sessionId) {
		return "recordings/" + sessionId + "/" + UUID.randomUUID() + ".cast.enc";
	}

	// Land an (opaque, "encrypted") object at objectKey via the real presigned PUT
	// so replay/delete operate on a genuine WORM object.
	protected void putObject(String objectKey, String wormMode, byte[] ciphertext) throws Exception {
		Instant retainUntil = Instant.now().plus(Duration.ofDays(1));
		RecordingStore.PresignedAccess upload = worm.ensureReady()
				.then(worm.presignUpload(objectKey, wormMode, retainUntil)).block();
		HttpRequest.Builder put = HttpRequest.newBuilder(URI.create(upload.url())).method(upload.method(),
				HttpRequest.BodyPublishers.ofByteArray(ciphertext));
		upload.requiredHeaders().forEach((name, value) -> {
			if (!isRestricted(name)) {
				put.header(name, value);
			}
		});
		int status = HttpClient.newHttpClient().send(put.build(), HttpResponse.BodyHandlers.discarding()).statusCode();
		if (status != 200) {
			throw new IllegalStateException("seed PUT failed: " + status);
		}
	}

	protected byte[] fetch(String url) throws Exception {
		return HttpClient.newHttpClient()
				.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofByteArray())
				.body();
	}

	protected S3Client adminS3() {
		return S3Client.builder().region(Region.of(wormProperties.getRegion()))
				.endpointOverride(URI.create(wormProperties.getEndpoint()))
				.credentialsProvider(StaticCredentialsProvider.create(
						AwsBasicCredentials.create(wormProperties.getAccessKey(), wormProperties.getSecretKey())))
				.serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build()).build();
	}

	protected ObjectNode nodeLabelScope(String key, String value) {
		ObjectNode scope = json.createObjectNode();
		scope.set("node_labels", json.createObjectNode().put(key, value));
		return scope;
	}

	/**
	 * Mint a bearer for a fresh service account granted {@code permissions} under
	 * {@code scope}.
	 */
	protected String tokenScoped(String saName, JsonNode scope, String... permissions) {
		ServiceAccount sa = serviceAccounts
				.save(ServiceAccount.create(saName, "test", "client_secret", null, null, "api")).block();
		var issued = machineIdentity.issueCredential(sa.id(), "client_secret", null, null, null, null, "admin").block();
		PlatformRole role = roles
				.save(PlatformRole.create("role-" + UUID.randomUUID(), List.of(permissions), "test", "default"))
				.block();
		bindings.save(RoleBinding.create(role.id(), "user", saName, scope, "default")).block();
		var token = machineIdentity.issueToken(new MachineIdentityService.TokenRequest("client_credentials", saName,
				null, null, issued.clientSecret(), null), null, "203.0.113.30").block();
		return token.accessToken();
	}

	private static boolean isRestricted(String header) {
		return header.equalsIgnoreCase("host") || header.equalsIgnoreCase("content-length");
	}

	protected static String unique() {
		return UUID.randomUUID().toString().substring(0, 8);
	}
}
