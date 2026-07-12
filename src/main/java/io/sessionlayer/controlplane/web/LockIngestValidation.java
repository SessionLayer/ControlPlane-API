package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.api.model.LockTarget;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.JsonNodeFactory;
import tools.jackson.databind.node.ObjectNode;

/**
 * Ingest validation for the lock CRUD (D5; closes the S5 {@code
 * A-lock-ingest-validation} recommendation). A lock is the top-tier
 * un-overridable deny, so a malformed target could silently over- or
 * under-block: reject it up front. The rules:
 * <ul>
 * <li>the target must name at least one recognised facet, OR set
 * {@code all=true} — a fleet-wide lock is never the result of a typo;</li>
 * <li>no blank string inside any facet;</li>
 * <li>every {@code nodeLabels} entry parses as {@code "key=value"} with a
 * non-blank key;</li>
 * <li>an explicit TTL is positive.</li>
 * </ul>
 * On success it returns the canonical {@code target_selector} jsonb (the frozen
 * {@code LockTarget} plural shape) the CP persists and the feed converts back
 * to the wire target.
 */
final class LockIngestValidation {

	private static final JsonNodeFactory JSON = JsonNodeFactory.instance;

	private LockIngestValidation() {
	}

	static ObjectNode toSelector(LockTarget target) {
		if (target == null) {
			throw invalid("a lock target is required");
		}
		ObjectNode selector = JSON.objectNode();
		boolean any = false;
		any |= putStrings(selector, "identities", target.getIdentities(), "identities");
		any |= putStrings(selector, "groups", target.getGroups(), "groups");
		any |= putStrings(selector, "principals", target.getPrincipals(), "principals");
		any |= putLabels(selector, target.getNodeLabels());
		any |= putNodeIds(selector, target.getNodeIds());
		boolean all = Boolean.TRUE.equals(target.getAll());
		if (all) {
			selector.put("all", true);
		}
		if (!any && !all) {
			throw invalid("a lock target must name at least one facet, or set all:true for an intentional "
					+ "fleet-wide lock");
		}
		return selector;
	}

	static Integer normalizeTtl(Long ttlSeconds) {
		if (ttlSeconds == null) {
			return null; // no expiry — the lock stands until released
		}
		if (ttlSeconds <= 0 || ttlSeconds > Integer.MAX_VALUE) {
			throw invalid("ttlSeconds must be a positive number of seconds");
		}
		return ttlSeconds.intValue();
	}

	/** A short, secret-free audit summary of the facets a lock targets. */
	static String summarize(ObjectNode selector) {
		return selector.properties().stream()
				.map(entry -> entry.getKey() + (entry.getValue().isArray() ? ":" + entry.getValue().size() : ""))
				.collect(Collectors.joining(","));
	}

	private static boolean putStrings(ObjectNode selector, String key, List<String> values, String facet) {
		if (values == null || values.isEmpty()) {
			return false;
		}
		ArrayNode array = JSON.arrayNode();
		for (String value : values) {
			if (value == null || value.isBlank()) {
				throw invalid("a " + facet + " entry must not be blank");
			}
			array.add(value.trim());
		}
		selector.set(key, array);
		return true;
	}

	private static boolean putLabels(ObjectNode selector, List<String> labels) {
		if (labels == null || labels.isEmpty()) {
			return false;
		}
		ArrayNode array = JSON.arrayNode();
		for (String label : labels) {
			if (label == null || label.isBlank()) {
				throw invalid("a nodeLabels entry must not be blank");
			}
			int eq = label.indexOf('=');
			if (eq <= 0) {
				throw invalid("a nodeLabels entry must be \"key=value\" with a non-blank key");
			}
			array.add(label.trim());
		}
		selector.set("node_labels", array);
		return true;
	}

	private static boolean putNodeIds(ObjectNode selector, List<UUID> nodeIds) {
		if (nodeIds == null || nodeIds.isEmpty()) {
			return false;
		}
		ArrayNode array = JSON.arrayNode();
		for (UUID nodeId : nodeIds) {
			if (nodeId == null) {
				throw invalid("a nodeIds entry must be a valid UUID");
			}
			array.add(nodeId.toString());
		}
		selector.set("node_ids", array);
		return true;
	}

	private static LockValidationException invalid(String message) {
		return new LockValidationException(message);
	}
}
