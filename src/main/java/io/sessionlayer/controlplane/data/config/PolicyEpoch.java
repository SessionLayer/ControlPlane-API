package io.sessionlayer.controlplane.data.config;

import io.sessionlayer.controlplane.data.Uuids;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.annotation.Version;
import org.springframework.data.relational.core.mapping.Table;

/**
 * CONFIG · {@code config.policy_epoch} (F-DM-5). The authoritative monotonic
 * policy epoch (singleton) that decisions snapshot into {@code ssh_session} /
 * {@code audit_event}. S5 bumps it on any config change under the
 * {@code @Version} optimistic lock; a DB trigger rejects any decrease.
 */
@Table(schema = "config", name = "policy_epoch")
public record PolicyEpoch(@Id UUID id, boolean singleton, long epoch, @Version Long version,
		@LastModifiedDate Instant updatedAt) {

	/** The initial epoch 0. */
	public static PolicyEpoch initial() {
		return new PolicyEpoch(Uuids.v7(), true, 0L, null, null);
	}
}
