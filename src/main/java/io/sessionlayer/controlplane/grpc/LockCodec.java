package io.sessionlayer.controlplane.grpc;

import io.sessionlayer.controlplane.data.runtime.AccessLock;
import io.sessionlayer.controlplane.grpc.v1.Lock;
import io.sessionlayer.controlplane.grpc.v1.LockMode;
import io.sessionlayer.controlplane.grpc.v1.LockTarget;
import java.time.Instant;
import java.util.function.Consumer;
import tools.jackson.databind.JsonNode;

/**
 * Converts a persisted {@link AccessLock} to its wire {@link Lock}. The stored
 * {@code target_selector} jsonb is the frozen {@code LockTarget} plural shape
 * (identities/groups/node_ids/principals/node_labels/all); the S5 singular
 * facets are also folded in so a legacy singular row still serialises to a
 * faithful wire target rather than an empty (match-everything) one.
 */
final class LockCodec {

	private LockCodec() {
	}

	static Lock toProto(AccessLock lock) {
		return Lock.newBuilder().setLockId(lock.id().toString()).setTarget(toTarget(lock.targetSelector()))
				.setExpiresAtEpochSeconds(epoch(lock.expiresAt())).setCreatedAtEpochSeconds(epoch(lock.createdAt()))
				.setReason(nullToEmpty(lock.reason())).setMode(mode(lock.mode())).build();
	}

	// A persisted lock is always strict or best_effort (NOT NULL CHECK); a
	// null/unknown value maps to STRICT — the stronger, fail-safe deny.
	private static LockMode mode(String mode) {
		return "best_effort".equals(mode) ? LockMode.LOCK_MODE_BEST_EFFORT : LockMode.LOCK_MODE_STRICT;
	}

	static LockTarget toTarget(JsonNode selector) {
		LockTarget.Builder target = LockTarget.newBuilder();
		if (selector == null || !selector.isObject()) {
			return target.build();
		}
		addAll(selector, "identities", target::addIdentities);
		addAll(selector, "groups", target::addGroups);
		addAll(selector, "node_ids", target::addNodeIds);
		addAll(selector, "principals", target::addPrincipals);
		addAll(selector, "node_labels", target::addNodeLabels);
		addOne(selector, "identity", target::addIdentities);
		addOne(selector, "group", target::addGroups);
		addOne(selector, "node_id", target::addNodeIds);
		addOne(selector, "principal", target::addPrincipals);
		addNodeLabelObject(selector, target::addNodeLabels);
		if (selector.path("all").asBoolean(false)) {
			target.setAll(true);
		}
		return target.build();
	}

	private static void addAll(JsonNode selector, String key, Consumer<String> sink) {
		JsonNode array = selector.get(key);
		if (array == null || !array.isArray()) {
			return;
		}
		for (JsonNode element : array) {
			if (element.isString()) {
				sink.accept(element.stringValue());
			}
		}
	}

	private static void addOne(JsonNode selector, String key, Consumer<String> sink) {
		JsonNode value = selector.get(key);
		if (value != null && value.isString()) {
			sink.accept(value.stringValue());
		}
	}

	private static void addNodeLabelObject(JsonNode selector, Consumer<String> sink) {
		JsonNode label = selector.get("node_label");
		if (label == null || !label.isObject()) {
			return;
		}
		JsonNode key = label.get("key");
		JsonNode value = label.get("value");
		if (key != null && key.isString() && value != null && value.isString()) {
			sink.accept(key.stringValue() + "=" + value.stringValue());
		}
	}

	private static long epoch(Instant instant) {
		return instant == null ? 0L : instant.getEpochSecond();
	}

	private static String nullToEmpty(String value) {
		return value == null ? "" : value;
	}
}
