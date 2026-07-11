package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * RUNTIME · {@code runtime.pin} (Design §5.5). An authN-shortcut pin
 * {@code {fingerprint, identity, source-cidr, principals, expiry}}.
 * {@code sourceCidr} is stored as text with a {@code ::cidr} format CHECK
 * (driver has no cidr codec; see {@code docs/DATA-MODEL.md} §9).
 */
@Table(schema = "runtime", name = "pin")
public record Pin(@Id UUID id, String fingerprint, String identity, String sourceCidr, List<String> principals,
		Instant expiresAt, Instant revokedAt, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static Pin create(String fingerprint, String identity, String sourceCidr, List<String> principals,
			Instant expiresAt) {
		return new Pin(Uuids.v7(), fingerprint, identity, sourceCidr, principals, expiresAt, null, null, null, null);
	}

	/**
	 * Re-pin (extend/rebind) an existing row, keeping its id + optimistic version.
	 */
	public Pin reissued(String sourceCidr, List<String> principals, Instant expiresAt) {
		return new Pin(id, fingerprint, identity, sourceCidr, principals, expiresAt, null, version, createdAt,
				updatedAt);
	}

	public Pin revoked(Instant at) {
		return new Pin(id, fingerprint, identity, sourceCidr, principals, expiresAt, at, version, createdAt, updatedAt);
	}

	public boolean active(Instant now) {
		return revokedAt == null && expiresAt.isAfter(now);
	}
}
