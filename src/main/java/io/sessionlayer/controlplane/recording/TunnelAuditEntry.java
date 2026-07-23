package io.sessionlayer.controlplane.recording;

/**
 * One admitted port-forward/X11 tunnel's audit facts (metadata only — forwarded
 * byte content is never captured, S29 FR-SESS-2). {@code target} is empty for
 * X11 (no client-supplied target).
 */
public record TunnelAuditEntry(String capability, String direction, String target, long bytesIn, long bytesOut,
		long durationSeconds) {
}
