package io.sessionlayer.controlplane.data.config;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * CONFIG · {@code config.ca_config} (FR-CA-1/4/7). Per-CA (user|session|host)
 * backend + key <b>reference</b> (never private key material) + algorithm
 * (default ECDSA P-256). A CA kind may have several rows during a rotation
 * overlap ({@code rotationState} incoming/active/outgoing/expired); exactly one
 * is {@code active} (partial unique index). {@code name} is the stable unique
 * key. S3 owns the rotation state machine.
 */
@Table(schema = "config", name = "ca_config")
public record CaConfig(@Id UUID id, String name, String caKind, String backend, String keyReference, String algorithm,
		String rotationState, String origin, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static CaConfig create(String name, String caKind, String backend, String keyReference, String algorithm,
			String rotationState, String origin) {
		return new CaConfig(Uuids.v7(), name, caKind, backend, keyReference, algorithm, rotationState, origin, null,
				null, null);
	}
}
