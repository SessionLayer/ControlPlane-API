package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * RUNTIME · {@code runtime.ca_key_material} (FR-CA-8). The KEK-wrapped local-CA
 * private key ({@code wrappedKey} is ciphertext, never plaintext) plus the
 * public key (public material). The KEK is env-sourced, never in the DB, so a
 * datastore-only compromise yields ciphertext it cannot unwrap.
 * {@code caConfigId} is a snapshot reference to {@code config.ca_config} (no
 * FK).
 *
 * <p>
 * {@code caCertificate} (Session Four, V14) holds the self-signed X.509 CA
 * certificate (DER) for X.509 CA rows (the internal {@code mtls} CA); it is
 * {@code null} for the SSH CAs, whose trust anchor is an OpenSSH public key
 * rather than an X.509 certificate. Public material — write-once (V14 trigger).
 */
@Table(schema = "runtime", name = "ca_key_material")
public record CaKeyMaterial(@Id UUID id, UUID caConfigId, String caConfigName, String wrapAlgorithm,
		String kekReference, byte[] wrappedKey, byte[] iv, byte[] publicKey, String keyType, byte[] caCertificate,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	/** SSH-CA material (no X.509 CA certificate). */
	public static CaKeyMaterial create(UUID caConfigId, String caConfigName, String kekReference, byte[] wrappedKey,
			byte[] iv, byte[] publicKey, String keyType) {
		return create(caConfigId, caConfigName, kekReference, wrappedKey, iv, publicKey, keyType, null);
	}

	/** X.509-CA material carrying the self-signed CA certificate (DER). */
	public static CaKeyMaterial create(UUID caConfigId, String caConfigName, String kekReference, byte[] wrappedKey,
			byte[] iv, byte[] publicKey, String keyType, byte[] caCertificate) {
		return new CaKeyMaterial(Uuids.v7(), caConfigId, caConfigName, "AES-256-GCM", kekReference, wrappedKey, iv,
				publicKey, keyType, caCertificate, null, null, null);
	}
}
