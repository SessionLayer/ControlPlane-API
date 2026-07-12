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
 * CONFIG · {@code config.operator_settings} (F-DM-9). The singleton
 * cluster-configuration row that cold start (FR-BOOT-1 / §5.5) reads to
 * provision the three CAs, and that later sessions read for retention / WORM /
 * OTP / session-limit defaults and the FR-BOOT-2 first-admin bootstrap
 * self-disable flag ({@code bootstrapCompleted}). {@code kekReference} is a
 * reference to the local-CA KEK (env var name / KMS handle), never the KEK
 * bytes. Singleton is DB-enforced ({@code singleton boolean UNIQUE CHECK}).
 */
@Table(schema = "config", name = "operator_settings")
public record OperatorSettings(@Id UUID id, boolean singleton, String kekReference, String defaultCaBackend,
		int auditRetentionDays, String defaultWormMode, int otpTtlSeconds, Integer defaultMaxSessionSeconds,
		Integer defaultIdleTimeoutSeconds, Integer defaultMaxConcurrentSessions, String bootstrapAdminSubject,
		String bootstrapCredentialHash, boolean bootstrapCompleted, Instant bootstrapCompletedAt,
		byte[] recordingCustomerPublicKey, String recordingKeySealAlgorithm, String recordingKeyRef,
		int recordingRetentionDays, boolean recordingStrictDefault, String origin, @Version Long version,
		@CreatedDate Instant createdAt, @LastModifiedDate Instant updatedAt) {

	/**
	 * Cold-start defaults (FR-AUD-6 retention 365d, governance WORM, local CA). The
	 * customer recording key ({@code recordingCustomerPublicKey}) is deliberately
	 * <b>unset</b> — recording is un-provisioned until an operator supplies it, and
	 * {@code BeginRecording} fails closed rather than store keystrokes in the clear
	 * (FR-AUD-2, §15).
	 */
	public static OperatorSettings defaults() {
		return new OperatorSettings(Uuids.v7(), true, null, "local", 365, "governance", 120, null, null, null, null,
				null, false, null, null, "ecies_p256", null, 365, true, "default", null, null, null);
	}
}
