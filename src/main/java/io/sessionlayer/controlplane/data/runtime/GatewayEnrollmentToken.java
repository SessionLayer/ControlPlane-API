package io.sessionlayer.controlplane.data.runtime;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * RUNTIME · {@code runtime.gateway_enrollment_token} (Design §4.B / FR-JOIN-3).
 * The operator-provisioned bootstrap credential a Gateway presents to
 * {@code EnrollGateway}. Single-use, short-TTL, self-destruct. Stores
 * {@code tokenHash} only — the raw token is <b>never</b> persisted (mirrors
 * {@link JoinToken}/{@link Otp}); the atomic single-use marker is
 * {@code consumedAt}. Scoped to a single {@code gatewayName}. This is the
 * reusable token-mint/validate shape agents will reuse in S12.
 */
@Table(schema = "runtime", name = "gateway_enrollment_token")
public record GatewayEnrollmentToken(@Id UUID id, String tokenHash, String gatewayName, boolean singleUse,
		Instant expiresAt, Instant consumedAt, String createdBy, @Version Long version, @CreatedDate Instant createdAt) {

	public static GatewayEnrollmentToken create(String tokenHash, String gatewayName, Instant expiresAt,
			String createdBy) {
		return new GatewayEnrollmentToken(Uuids.v7(), tokenHash, gatewayName, true, expiresAt, null, createdBy, null,
				null);
	}
}
