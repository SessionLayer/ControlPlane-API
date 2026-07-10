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
 * CONFIG · {@code config.capability_def} (Design §12A). The
 * requestable-capability catalogue ({@code name} is CHECK-constrained to the
 * capability enum).
 */
@Table(schema = "config", name = "capability_def")
public record CapabilityDef(@Id UUID id, String name, String description, String origin, @Version Long version,
		@CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static CapabilityDef create(String name, String description, String origin) {
		return new CapabilityDef(Uuids.v7(), name, description, origin, null, null, null);
	}
}
