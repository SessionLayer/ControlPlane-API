package io.sessionlayer.controlplane.recording;

import jakarta.annotation.PreDestroy;
import java.net.URI;
import java.time.Duration;
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
import software.amazon.awssdk.services.s3.model.DeleteMarkerEntry;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest;
import software.amazon.awssdk.services.s3.model.NoSuchBucketException;
import software.amazon.awssdk.services.s3.model.ObjectLockMode;
import software.amazon.awssdk.services.s3.model.ObjectVersion;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;

/**
 * The S3-compatible WORM {@link RecordingStore} — the current recording
 * object-store backend (Design §12.2, FR-AUD-3). The CP never touches recording
 * bytes: it ensures the bucket exists with S3 <b>object-lock enabled</b>,
 * issues a short-lived single-object presigned PUT with the object-lock mode +
 * retain-until baked into the signature (so the Gateway uploads ciphertext
 * directly and <b>cannot strip the WORM lock</b>), issues a short-lived
 * presigned GET for admin replay/export (the object stays customer-key
 * encrypted — the CP cannot decrypt it), and performs governance-mode deletion
 * (compliance is refused, object-lock un-deletable).
 *
 * <p>
 * Bucket-ensure ({@link #ensureReady()}) does network I/O and is done EAGERLY
 * at startup (idempotently short-circuited thereafter) so it never runs inside
 * a request-path DB transaction. The presigns are pure local crypto (no
 * network). Every S3 call runs off the reactive event loop on the
 * bounded-elastic scheduler (non-blocking discipline).
 */
@Component
public class WormObjectStore implements RecordingStore {

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

	// Eagerly create the bucket at startup so the request path never does bucket
	// I/O
	// inside a DB transaction. Best-effort: if the store is down at boot, the guard
	// stays unset and the first upload re-ensures (fail-closed, not fail-boot).
	@EventListener(ApplicationReadyEvent.class)
	void warmUp() {
		ensureReady().subscribe(ignored -> {
		}, error -> LOG.warn("WORM bucket warm-up failed (will retry on first upload): {}", error.toString()));
	}

	@Override
	public Mono<Void> ensureReady() {
		return Mono.<Void>fromRunnable(this::ensureBucketBlocking).subscribeOn(Schedulers.boundedElastic());
	}

	@Override
	public Mono<PresignedAccess> presignUpload(String objectKey, String wormMode, Instant retainUntil) {
		return Mono.fromCallable(() -> presignUploadBlocking(objectKey, wormMode, retainUntil))
				.subscribeOn(Schedulers.boundedElastic());
	}

	@Override
	public Mono<PresignedAccess> presignDownload(String objectKey, Duration ttl) {
		return Mono.fromCallable(() -> presignDownloadBlocking(objectKey, ttl))
				.subscribeOn(Schedulers.boundedElastic());
	}

	@Override
	public Mono<Void> deleteObject(String objectKey, String wormMode) {
		// Compliance objects are truly un-deletable (object-lock); refuse in-app too so
		// the intent is explicit and we never even attempt a call the store would
		// reject
		// (FR-AUD-3).
		if ("compliance".equals(wormMode)) {
			return Mono.error(new UnsupportedOperationException("compliance-mode recordings are un-deletable"));
		}
		// Object-lock ⇒ VERSIONED bucket: a key-only delete just writes a delete marker
		// and the governance-locked VERSION survives (GetObjectVersion still returns
		// the
		// data) — GDPR erasure would be illusory + storage never reclaimed. Real
		// erasure
		// (FR-AUD-6) removes EVERY version + delete marker of the key, bypassing
		// governance retention (the caller's credential carries
		// s3:BypassGovernanceRetention).
		return Mono.<Void>fromRunnable(() -> deleteAllVersionsBlocking(objectKey))
				.subscribeOn(Schedulers.boundedElastic());
	}

	private void deleteAllVersionsBlocking(String objectKey) {
		String bucket = properties.getBucket();
		ListObjectVersionsRequest request = ListObjectVersionsRequest.builder().bucket(bucket).prefix(objectKey)
				.build();
		// prefix is a starts-with match, so filter to the EXACT key (a sibling key that
		// shares the prefix must not be erased).
		s3.listObjectVersionsPaginator(request).forEach(page -> {
			for (ObjectVersion version : page.versions()) {
				if (version.key().equals(objectKey)) {
					deleteVersion(bucket, objectKey, version.versionId());
				}
			}
			for (DeleteMarkerEntry marker : page.deleteMarkers()) {
				if (marker.key().equals(objectKey)) {
					deleteVersion(bucket, objectKey, marker.versionId());
				}
			}
		});
	}

	private void deleteVersion(String bucket, String key, String versionId) {
		s3.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(key).versionId(versionId)
				.bypassGovernanceRetention(true).build());
	}

	@Override
	public Mono<Void> probe() {
		return Mono
				.<Void>fromRunnable(
						() -> s3.headBucket(HeadBucketRequest.builder().bucket(properties.getBucket()).build()))
				.subscribeOn(Schedulers.boundedElastic());
	}

	private PresignedAccess presignUploadBlocking(String objectKey, String wormMode, Instant retainUntil) {
		PutObjectRequest put = PutObjectRequest.builder().bucket(properties.getBucket()).key(objectKey)
				.objectLockMode(objectLockMode(wormMode)).objectLockRetainUntilDate(retainUntil).build();
		PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
				.signatureDuration(properties.getCredentialTtl()).putObjectRequest(put).build();
		PresignedPutObjectRequest presigned = presigner.presignPutObject(presignRequest);
		// The signed headers are part of the signature — the Gateway MUST replay them
		// verbatim (they include x-amz-object-lock-* + host), so a value change breaks
		// the signature and the store refuses the PUT (the lock cannot be stripped).
		return new PresignedAccess(presigned.url().toString(), presigned.httpRequest().method().name(),
				signedHeaders(presigned.signedHeaders()), presigned.expiration().getEpochSecond());
	}

	// A read-only presigned GET for admin replay/export. No object-lock headers (a
	// GET does not mutate); the object remains customer-key encrypted end to end.
	private PresignedAccess presignDownloadBlocking(String objectKey, Duration ttl) {
		GetObjectRequest get = GetObjectRequest.builder().bucket(properties.getBucket()).key(objectKey).build();
		GetObjectPresignRequest presignRequest = GetObjectPresignRequest.builder().signatureDuration(ttl)
				.getObjectRequest(get).build();
		PresignedGetObjectRequest presigned = presigner.presignGetObject(presignRequest);
		return new PresignedAccess(presigned.url().toString(), presigned.httpRequest().method().name(),
				signedHeaders(presigned.signedHeaders()), presigned.expiration().getEpochSecond());
	}

	private static Map<String, String> signedHeaders(Map<String, List<String>> signed) {
		return signed.entrySet().stream()
				.collect(Collectors.toMap(Map.Entry::getKey, entry -> String.join(",", entry.getValue())));
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
