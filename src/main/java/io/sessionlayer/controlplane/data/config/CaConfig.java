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
 * CONFIG · {@code config.ca_config} (FR-CA-1/4). Per-CA (user|session|host)
 * backend + key <b>reference</b> (never private key material) + algorithm
 * (default ECDSA P-256). {@code caKind} is UNIQUE (one config per CA kind).
 */
@Table(schema = "config", name = "ca_config")
public record CaConfig(@Id UUID id, String caKind, String backend, String keyReference, String algorithm, String origin,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static CaConfig create(String caKind, String backend, String keyReference, String algorithm, String origin) {
		return new CaConfig(Uuids.v7(), caKind, backend, keyReference, algorithm, origin, null, null, null);
	}
}
