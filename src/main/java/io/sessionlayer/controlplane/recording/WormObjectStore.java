package io.sessionlayer.controlplane.recording;

import jakarta.annotation.PreDestroy;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.BucketAlreadyExistsException;
import software.amazon.awssdk.services.s3.model.BucketAlreadyOwnedByYouException;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.ObjectLockMode;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

/**
 * The WORM object store for session recordings (Design §12.2, FR-AUD-3). The CP
 * never touches recording bytes: it ensures the bucket exists with S3
 * <b>object-lock enabled</b> and issues a short-lived, single-object presigned
 * PUT with the object-lock mode + retain-until baked into the signature, so the
 * Gateway uploads the ciphertext directly and <b>cannot strip the WORM lock</b>
 * (changing any signed header breaks the signature → the store rejects the
 * PUT).
 *
 * <p>
 * Bucket-ensure ({@link #ensureBucket()}) does network I/O and is done EAGERLY
 * at startup (and idempotently short-circuited thereafter) so it never runs
 * inside a request-path DB transaction (reliability). The presign
 * ({@link #presign}) is pure local crypto (no network). Both run off the
 * reactive event loop on the bounded-elastic scheduler (non-blocking
 * discipline).
 */
@Component
public class WormObjectStore {

	private static final Logger LOG = LoggerFactory.getLogger(WormObjectStore.class);

	private final WormProperties properties;
	private final S3Client s3;
	private final S3Presigner presigner;
	private final AtomicBoolean bucketEnsured = new AtomicBoolean(false);

	public WormObjectStore(WormProperties properties) {
		this.properties = properties;
		AwsCredentialsProvider credentials = credentialsProvider(properties);
		Region region = Region.of(properties.getRegion());
		S3Configuration serviceConfig = S3Configuration.builder().pathStyleAccessEnabled(properties.isPathStyleAccess())
				.build();
		URI endpoint = endpointUri(properties.getEndpoint());

		var clientBuilder = S3Client.builder().region(region).credentialsProvider(credentials)
				.serviceConfiguration(serviceConfig);
		var presignerBuilder = S3Presigner.builder().region(region).credentialsProvider(credentials)
				.serviceConfiguration(serviceConfig);
		if (endpoint != null) {
			clientBuilder.endpointOverride(endpoint);
			presignerBuilder.endpointOverride(endpoint);
		}
		this.s3 = clientBuilder.build();
		this.presigner = presignerBuilder.build();
	}

	/** A presigned single-object upload: the URL, method, and headers to replay. */
	public record PresignedUpload(String url, String method, Map<String, String> requiredHeaders,
			long expiresAtEpochSeconds) {
	}

	// Eagerly create the bucket at startup so the request path never does bucket
	// I/O
	// inside a DB transaction. Best-effort: if the store is down at boot, the guard
	// stays unset and the first RequestUpload re-ensures (fail-closed, not
	// fail-boot).
	@EventListener(ApplicationReadyEvent.class)
	void warmUp() {
		ensureBucket().subscribe(ignored -> {
		}, error -> LOG.warn("WORM bucket warm-up failed (will retry on first upload): {}", error.toString()));
	}

	/**
	 * Ensure the WORM bucket exists with object-lock enabled. Idempotent + short-
	 * circuited after the first success; runs off the event loop.
	 */
	public Mono<Void> ensureBucket() {
		return Mono.<Void>fromRunnable(this::ensureBucketBlocking).subscribeOn(Schedulers.boundedElastic());
	}

	/**
	 * Presign a single-object PUT scoped to {@code objectKey} with the WORM mode +
	 * {@code retainUntil} locked into the signature. Pure local crypto (no
	 * network); the caller is responsible for having ensured the bucket. Runs off
	 * the event loop.
	 */
	public Mono<PresignedUpload> presign(String objectKey, String wormMode, Instant retainUntil) {
		return Mono.fromCallable(() -> presignBlocking(objectKey, wormMode, retainUntil))
				.subscribeOn(Schedulers.boundedElastic());
	}

	/**
	 * Liveness probe for the health indicator: HEAD the bucket. Off the event loop.
	 */
	public Mono<Void> probe() {
		return Mono
				.<Void>fromRunnable(
						() -> s3.headBucket(HeadBucketRequest.builder().bucket(properties.getBucket()).build()))
				.subscribeOn(Schedulers.boundedElastic());
	}

	private PresignedUpload presignBlocking(String objectKey, String wormMode, Instant retainUntil) {
		PutObjectRequest put = PutObjectRequest.builder().bucket(properties.getBucket()).key(objectKey)
				.objectLockMode(objectLockMode(wormMode)).objectLockRetainUntilDate(retainUntil).build();
		PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
				.signatureDuration(properties.getCredentialTtl()).putObjectRequest(put).build();
		PresignedPutObjectRequest presigned = presigner.presignPutObject(presignRequest);
		// The signed headers are part of the signature — the Gateway MUST replay them
		// verbatim (they include x-amz-object-lock-* + host), so a value change breaks
		// the signature and the store refuses the PUT (the lock cannot be stripped).
		Map<String, String> headers = presigned.signedHeaders().entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, entry -> String.join(",", entry.getValue())));
		return new PresignedUpload(presigned.url().toString(), presigned.httpRequest().method().name(), headers,
				presigned.expiration().getEpochSecond());
	}

	// Create-if-absent WITH object-lock enabled (which also turns on versioning).
	// An
	// existing bucket is assumed correctly configured (created by us or the
	// operator).
	private void ensureBucketBlocking() {
		if (bucketEnsured.get()) {
			return;
		}
		String bucket = properties.getBucket();
		try {
			s3.headBucket(HeadBucketRequest.builder().bucket(bucket).build());
		} catch (NoSuchBucketException absent) {
			createBucket(bucket);
		} catch (S3Exception maybeMissing) {
			if (maybeMissing.statusCode() == 404) {
				createBucket(bucket);
			} else {
				throw maybeMissing;
			}
		}
		bucketEnsured.set(true);
	}

	private void createBucket(String bucket) {
		try {
			s3.createBucket(CreateBucketRequest.builder().bucket(bucket).objectLockEnabledForBucket(true).build());
			LOG.info("created WORM recording bucket {} (object-lock enabled)", bucket);
		} catch (BucketAlreadyOwnedByYouException | BucketAlreadyExistsException raced) {
			LOG.debug("WORM bucket {} already present (concurrent ensure)", bucket);
		}
	}

	private static ObjectLockMode objectLockMode(String wormMode) {
		return "compliance".equals(wormMode) ? ObjectLockMode.COMPLIANCE : ObjectLockMode.GOVERNANCE;
	}

	private static AwsCredentialsProvider credentialsProvider(WormProperties properties) {
		if (properties.getAccessKey() != null && !properties.getAccessKey().isBlank()) {
			return StaticCredentialsProvider
					.create(AwsBasicCredentials.create(properties.getAccessKey(), properties.getSecretKey()));
		}
		return DefaultCredentialsProvider.create();
	}

	private static URI endpointUri(String endpoint) {
		return (endpoint == null || endpoint.isBlank()) ? null : URI.create(endpoint);
	}

	@PreDestroy
	void close() {
		for (AutoCloseable closeable : List.of(s3, presigner)) {
			try {
				closeable.close();
			} catch (Exception ignored) {
				LOG.debug("error closing WORM S3 client (shutdown)");
			}
		}
	}
}
