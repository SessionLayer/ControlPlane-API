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
 * RUNTIME · {@code runtime.device_flow} (F-DM-13 / FR-AUTH-3, Design §5.2/§15).
 * RFC 8628 device-flow state. Stores <b>hashes</b> of the device/user codes
 * (never raw). {@code connectionBinding} is the 1:1 device_code↔connection
 * anti-phishing binding (§15). Behaviour is S6; this session persists the
 * shape.
 */
@Table(schema = "runtime", name = "device_flow")
public record DeviceFlow(@Id UUID id, String deviceCodeHash, String userCodeHash, String identity, String status,
		String connectionBinding, String sourceIp, int intervalSeconds, Instant expiresAt, Instant lastPolledAt,
		Instant authorizedAt, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static DeviceFlow create(String deviceCodeHash, String userCodeHash, String connectionBinding,
			String sourceIp, int intervalSeconds, Instant expiresAt) {
		return new DeviceFlow(Uuids.v7(), deviceCodeHash, userCodeHash, null, "pending", connectionBinding, sourceIp,
				intervalSeconds, expiresAt, null, null, null, null, null);
	}
}
