package io.sessionlayer.controlplane.recording;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import reactor.core.publisher.Mono;

/**
 * The pluggable recording object-store seam (owner requirement, Design §12.2).
 * The CP <b>never touches recording bytes and cannot decrypt them</b> — it only
 * ensures the WORM store is ready, issues short-lived single-object presigned
 * URLs (PUT for the Gateway's upload, GET for admin replay/export), and
 * performs governance-mode deletion. The current backend is an S3-compatible
 * WORM store ({@link WormObjectStore}); another object store (AWS S3 / GCS /
 * Azure Blob / MinIO) plugs in behind this interface.
 */
public interface RecordingStore {

	/** Ensure the store/bucket exists with object-lock enabled (idempotent). */
	Mono<Void> ensureReady();

	/**
	 * Presign a single-object PUT with the WORM mode + {@code retainUntil} locked
	 * into the signature, so the uploader cannot strip the object-lock (S9 write
	 * path). Bytes never traverse the CP.
	 */
	Mono<PresignedAccess> presignUpload(String objectKey, String wormMode, Instant retainUntil);

	/**
	 * Presign a short-lived single-object GET for admin replay/export (FR-AUD-5).
	 * The object stays customer-key encrypted; the CP returns only the URL, never
	 * plaintext, and cannot decrypt it. When {@code objectVersionId} is non-null
	 * the GET is PINNED to that finalized version so a later shadow PUT to the same
	 * key (by a compromised CP/Gateway) is never served (F-recording-worm-version-1
	 * / §15); null falls back to the current version (N-1 recording with no stored
	 * id).
	 */
	Mono<PresignedAccess> presignDownload(String objectKey, String objectVersionId, Duration ttl);

	/**
	 * Governance-mode deletion of a single object (FR-AUD-3/6, the GDPR erasure
	 * escape hatch). MUST fail closed for a {@code compliance}-mode object (truly
	 * un-deletable, object-lock). Idempotent — deleting an absent object succeeds.
	 */
	Mono<Void> deleteObject(String objectKey, String wormMode);

	/** Liveness probe (HEAD the store) for the health indicator. */
	Mono<Void> probe();

	/**
	 * A presigned single-object access: the URL, the HTTP method to use against it,
	 * any signed headers the caller MUST replay verbatim, and the absolute expiry.
	 */
	record PresignedAccess(String url, String method, Map<String, String> requiredHeaders, long expiresAtEpochSeconds) {
	}
}
