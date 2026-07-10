package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * RUNTIME · {@code runtime.otp} (Design §5.4 / FR-AUTH-9). A single-use OTP.
 * Stores {@code otpHash} only — the raw OTP is <b>never</b> persisted. The
 * atomic mark-used column ({@code used}) lives here.
 */
@Table(schema = "runtime", name = "otp")
public record Otp(@Id UUID id, String otpHash, String identity, List<String> allowedPrincipals, String sourceCidr,
		Instant expiresAt, boolean used, Instant usedAt, @Version Long version, @CreatedDate Instant createdAt) {

	public static Otp create(String otpHash, String identity, List<String> allowedPrincipals, String sourceCidr,
			Instant expiresAt) {
		return new Otp(Uuids.v7(), otpHash, identity, allowedPrincipals, sourceCidr, expiresAt, false, null, null,
				null);
	}
}
