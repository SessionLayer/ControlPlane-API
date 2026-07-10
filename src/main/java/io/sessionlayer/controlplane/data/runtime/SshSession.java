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
 * RUNTIME · {@code runtime.ssh_session} — the Design §12A "session" entity
 * (renamed; {@code session} is a reserved word, §7.1). Carries the <b>decision
 * snapshot</b> (§6): {@code matchedRuleId} (a plain uuid, no FK to
 * {@code config.dp_rule}), plus the resolved {@code principal},
 * {@code capabilities}, {@code accessModel}, and {@code policyEpoch} captured
 * at decision time, so history survives config GC.
 */
@Table(schema = "runtime", name = "ssh_session")
public record SshSession(@Id UUID id, String identity, UUID nodeId, String nodeName, String principal, UUID gatewayId,
		String gatewayName, String accessModel, List<String> capabilities, UUID matchedRuleId, String matchedRuleName,
		UUID jitRequestId, UUID breakglassActivationId, Long policyEpoch, Instant grantExpiry, Instant startedAt,
		Instant endedAt, String endReason, @Version Long version, @CreatedDate Instant createdAt,
		@LastModifiedDate Instant updatedAt) {

	public static SshSession create(String identity, UUID nodeId, String nodeName, String principal, UUID gatewayId,
			String gatewayName, String accessModel, List<String> capabilities, UUID matchedRuleId,
			String matchedRuleName, UUID jitRequestId, UUID breakglassActivationId, Long policyEpoch,
			Instant grantExpiry, Instant startedAt) {
		return new SshSession(Uuids.v7(), identity, nodeId, nodeName, principal, gatewayId, gatewayName, accessModel,
				capabilities, matchedRuleId, matchedRuleName, jitRequestId, breakglassActivationId, policyEpoch,
				grantExpiry, startedAt, null, null, null, null, null);
	}
}
