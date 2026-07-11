package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;
import tools.jackson.databind.JsonNode;

/**
 * RUNTIME · {@code runtime.device_flow} (FR-AUTH-3, Design §5.2/§15). Device
 * (RFC 8628) flow state. Stores <b>hashes</b> of the device/user codes (never
 * raw). {@code connectionBinding} is the 1:1 device_code↔connection
 * anti-phishing binding (§15).
 * {@code approverSourceIp}/{@code approverContext}/ {@code sourceContextMatch}
 * carry the §5.2 source-context correlation captured at the CP verification
 * page (a deny-only reducer, FR-AUTH-15). Status:
 * {@code pending → authorized|denied|expired}.
 */
@Table(schema = "runtime", name = "device_flow")
public record DeviceFlow(@Id UUID id, String deviceCodeHash, String userCodeHash, String identity, String status,
		String connectionBinding, String sourceIp, int intervalSeconds, Instant expiresAt, Instant lastPolledAt,
		Instant authorizedAt, String approverSourceIp, JsonNode approverContext, Boolean sourceContextMatch,
		@Version Long version, @CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	public static DeviceFlow create(String deviceCodeHash, String userCodeHash, String connectionBinding,
			String sourceIp, int intervalSeconds, Instant expiresAt) {
		return new DeviceFlow(Uuids.v7(), deviceCodeHash, userCodeHash, null, "pending", connectionBinding, sourceIp,
				intervalSeconds, expiresAt, null, null, null, null, null, null, null, null);
	}

	/** Approve the flow, recording the resolved identity + source correlation. */
	public DeviceFlow authorized(String identity, Instant at, String approverSourceIp, JsonNode approverContext,
			Boolean sourceContextMatch) {
		return new DeviceFlow(id, deviceCodeHash, userCodeHash, identity, "authorized", connectionBinding, sourceIp,
				intervalSeconds, expiresAt, lastPolledAt, at, approverSourceIp, approverContext, sourceContextMatch,
				version, createdAt, updatedAt);
	}

	public DeviceFlow withStatus(String newStatus) {
		return new DeviceFlow(id, deviceCodeHash, userCodeHash, identity, newStatus, connectionBinding, sourceIp,
				intervalSeconds, expiresAt, lastPolledAt, authorizedAt, approverSourceIp, approverContext,
				sourceContextMatch, version, createdAt, updatedAt);
	}
}
