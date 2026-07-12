package io.sessionlayer.controlplane.recording;

import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * WORM object-store configuration for session recordings
 * ({@code sessionlayer.recording.worm.*}, Design §12.2). The dev defaults match
 * the parent {@code docker-compose.yml} MinIO (S3 API on {@code :9000},
 * {@code sessionlayer}/{@code sessionlayer-dev-secret}); production overrides
 * these to the real object store (AWS S3 / MinIO) and injects credentials from
 * the environment. When {@code accessKey} is blank the AWS default credentials
 * provider chain is used (IAM role in production). The identity/routing fields
 * are {@code @NotBlank} so a misconfigured deploy fails fast at binding rather
 * than at first upload (operability).
 */
@Validated
@ConfigurationProperties(prefix = "sessionlayer.recording.worm")
public class WormProperties {

	/** S3 endpoint override (MinIO). Blank uses the default AWS S3 endpoint. */
	@NotBlank
	private String endpoint = "http://localhost:9000";

	/** AWS region (MinIO ignores it, but the SDK requires one). */
	@NotBlank
	private String region = "us-east-1";

	/** The WORM bucket the encrypted recordings are written to (object-lock on). */
	@NotBlank
	private String bucket = "sessionlayer-recordings";

	/** Static access key (dev/MinIO); blank ⇒ AWS default credential chain. */
	private String accessKey = "sessionlayer";

	/** Static secret key (dev/MinIO). */
	private String secretKey = "sessionlayer-dev-secret";

	/** Path-style addressing (required by MinIO; harmless for S3). */
	private boolean pathStyleAccess = true;

	/**
	 * Presigned-upload credential TTL — short-lived, single-object (Design §12.2).
	 */
	private Duration credentialTtl = Duration.ofSeconds(120);

	public String getEndpoint() {
		return endpoint;
	}

	public void setEndpoint(String endpoint) {
		this.endpoint = endpoint;
	}

	public String getRegion() {
		return region;
	}

	public void setRegion(String region) {
		this.region = region;
	}

	public String getBucket() {
		return bucket;
	}

	public void setBucket(String bucket) {
		this.bucket = bucket;
	}

	public String getAccessKey() {
		return accessKey;
	}

	public void setAccessKey(String accessKey) {
		this.accessKey = accessKey;
	}

	public String getSecretKey() {
		return secretKey;
	}

	public void setSecretKey(String secretKey) {
		this.secretKey = secretKey;
	}

	public boolean isPathStyleAccess() {
		return pathStyleAccess;
	}

	public void setPathStyleAccess(boolean pathStyleAccess) {
		this.pathStyleAccess = pathStyleAccess;
	}

	public Duration getCredentialTtl() {
		return credentialTtl;
	}

	public void setCredentialTtl(Duration credentialTtl) {
		this.credentialTtl = credentialTtl;
	}
}
