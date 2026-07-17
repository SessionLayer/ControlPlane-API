package io.sessionlayer.controlplane.grpc;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.grpc.v1.Lock;
import io.sessionlayer.controlplane.grpc.v1.LockMode;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * {@link AccessLock} → wire {@link Lock} conversion, incl. singular
 * back-compat.
 */
class LockCodecTest {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	@Test
	void pluralSelectorMapsEveryFacetPlusTimestamps() {
		UUID id = UUID.randomUUID();
		Instant created = Instant.ofEpochSecond(1_700_000_000L);
		Instant expires = Instant.ofEpochSecond(1_700_003_600L);
		ObjectNode selector = JSON.objectNode();
		selector.set("identities", JSON.arrayNode().add("alice").add("bob"));
		selector.set("groups", JSON.arrayNode().add("admins"));
		selector.set("node_ids", JSON.arrayNode().add("22222222-2222-2222-2222-222222222222"));
		selector.set("principals", JSON.arrayNode().add("deploy"));
		selector.set("node_labels", JSON.arrayNode().add("env=prod"));

		AccessLock lock = new AccessLock(id, selector, "strict", 3600, expires, "incident", "admin", 0L, created,
				created);
		Lock proto = LockCodec.toProto(lock);

		assertThat(proto.getLockId()).isEqualTo(id.toString());
		assertThat(proto.getReason()).isEqualTo("incident");
		assertThat(proto.getCreatedAtEpochSeconds()).isEqualTo(1_700_000_000L);
		assertThat(proto.getExpiresAtEpochSeconds()).isEqualTo(1_700_003_600L);
		assertThat(proto.getTarget().getIdentitiesList()).containsExactly("alice", "bob");
		assertThat(proto.getTarget().getGroupsList()).containsExactly("admins");
		assertThat(proto.getTarget().getNodeIdsList()).containsExactly("22222222-2222-2222-2222-222222222222");
		assertThat(proto.getTarget().getPrincipalsList()).containsExactly("deploy");
		assertThat(proto.getTarget().getNodeLabelsList()).containsExactly("env=prod");
		assertThat(proto.getTarget().getAll()).isFalse();
	}

	@Test
	void explicitAllIsCarried() {
		AccessLock lock = AccessLock.create(JSON.objectNode().put("all", true), "strict", null, null, "shutdown",
				"admin");
		assertThat(LockCodec.toProto(lock).getTarget().getAll()).isTrue();
	}

	@Test
	void nullExpiryMapsToZero() {
		AccessLock lock = AccessLock.create(JSON.objectNode().put("all", true), "strict", null, null, "x", "admin");
		assertThat(LockCodec.toProto(lock).getExpiresAtEpochSeconds()).isZero();
	}

	// S20: the additive `mode` field reaches the Gateway (previously absent → every
	// pushed lock read as a teardown). A persisted lock is always strict or
	// best_effort; an unknown/null value fails safe to STRICT.
	@Test
	void carriesBestEffortModeOnTheWire() {
		AccessLock lock = AccessLock.create(JSON.objectNode().put("all", true), "best_effort", null, null, "soft",
				"admin");
		assertThat(LockCodec.toProto(lock).getMode()).isEqualTo(LockMode.LOCK_MODE_BEST_EFFORT);
	}

	@Test
	void carriesStrictModeOnTheWire() {
		AccessLock lock = AccessLock.create(JSON.objectNode().put("all", true), "strict", null, null, "hard", "admin");
		assertThat(LockCodec.toProto(lock).getMode()).isEqualTo(LockMode.LOCK_MODE_STRICT);
	}

	@Test
	void unknownModeFailsSafeToStrict() {
		AccessLock lock = AccessLock.create(JSON.objectNode().put("all", true), null, null, null, "x", "admin");
		assertThat(LockCodec.toProto(lock).getMode()).isEqualTo(LockMode.LOCK_MODE_STRICT);
	}

	@Test
	void singularFacetsFoldIntoThePluralWireTarget() {
		ObjectNode label = JSON.objectNode();
		label.set("node_label", JSON.objectNode().put("key", "env").put("value", "prod"));
		label.put("identity", "carol");
		AccessLock lock = AccessLock.create(label, "strict", null, null, "legacy", "admin");

		Lock proto = LockCodec.toProto(lock);
		assertThat(proto.getTarget().getIdentitiesList()).containsExactly("carol");
		assertThat(proto.getTarget().getNodeLabelsList()).containsExactly("env=prod");
	}
}
