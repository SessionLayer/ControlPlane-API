package io.sessionlayer.controlplane.platform;

import java.time.Instant;
import java.util.Map;

/**
 * The requested scope of a scopable platform action (FR-PADM-2) —
 * {@code recording:replay/export} against a specific target. A binding's stored
 * scope must <b>cover</b> this request. Any facet may be null (unspecified). A
 * {@code null} scope request means an unscoped/global action, which only an
 * unscoped binding can authorize.
 *
 * @param nodeLabels
 *            labels of the target node (for node-label-scoped bindings)
 * @param user
 *            the recording's subject user (for user-scoped bindings)
 * @param at
 *            when the action occurs (for time-windowed bindings)
 */
public record PlatformScope(Map<String, String> nodeLabels, String user, Instant at) {

	public PlatformScope {
		nodeLabels = (nodeLabels == null) ? Map.of() : Map.copyOf(nodeLabels);
	}
}
