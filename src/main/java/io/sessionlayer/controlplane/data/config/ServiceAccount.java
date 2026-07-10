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
 * CONFIG · {@code config.service_account} (FR-AUTH-12). The machine-consumer
 * <b>definition</b>; issued credentials are runtime. {@code keyReference} is a
 * public key / JWKS reference, never a secret.
 */
@Table(schema = "config", name = "service_account")
public record ServiceAccount(@Id UUID id, String name, String description, String authMethod, String keyReference,
		Integer tokenTtlSeconds, String origin, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static ServiceAccount create(String name, String description, String authMethod, String keyReference,
			Integer tokenTtlSeconds, String origin) {
		return new ServiceAccount(Uuids.v7(), name, description, authMethod, keyReference, tokenTtlSeconds, origin,
				null, null, null);
	}
}
