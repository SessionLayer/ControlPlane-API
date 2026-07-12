package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The Session-Ten additions to the SIGNED decision context: identity, groups
 * and node labels are serialised so the Gateway matches identity/group/label
 * locks against trusted data (never data it was merely told).
 */
class DecisionContextCodecTest {

	@Test
	void serialisesIdentityGroupsAndNodeLabels() {
		DecisionContext ctx = new DecisionContext(UUID.randomUUID(), "node-a", List.of("deploy"), List.of("shell"),
				"deploy", Instant.now().plusSeconds(3600), 7L, Duration.ofSeconds(45), UUID.randomUUID(),
				UUID.randomUUID(), "10.0.0.5", Instant.now(), "alice", List.of("admins", "oncall"),
				List.of("env=prod", "tier=db"));

		io.sessionlayer.controlplane.grpc.v1.DecisionContext proto = DecisionContextCodec.toProto(ctx);

		assertThat(proto.getIdentity()).isEqualTo("alice");
		assertThat(proto.getIdentityGroupsList()).containsExactly("admins", "oncall");
		assertThat(proto.getNodeLabelsList()).containsExactly("env=prod", "tier=db");
		// The pre-existing fields still map (regression guard on the additive change).
		assertThat(proto.getNodeName()).isEqualTo("node-a");
		assertThat(proto.getPrincipal()).isEqualTo("deploy");
		assertThat(proto.getPolicyEpoch()).isEqualTo(7L);
	}

	@Test
	void toleratesEmptyIdentityAndCollections() {
		DecisionContext ctx = new DecisionContext(UUID.randomUUID(), "node-b", List.of(), List.of(), "", Instant.now(),
				0L, Duration.ZERO, UUID.randomUUID(), UUID.randomUUID(), "", Instant.now(), null, List.of(), List.of());

		io.sessionlayer.controlplane.grpc.v1.DecisionContext proto = DecisionContextCodec.toProto(ctx);

		assertThat(proto.getIdentity()).isEmpty();
		assertThat(proto.getIdentityGroupsList()).isEmpty();
		assertThat(proto.getNodeLabelsList()).isEmpty();
	}
}
