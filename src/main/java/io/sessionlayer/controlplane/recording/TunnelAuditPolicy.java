package io.sessionlayer.controlplane.recording;

import io.sessionlayer.controlplane.authz.Capabilities;
import java.util.Set;

/**
 * Normalizes and bounds the per-tunnel (port-forward/X11) audit the Gateway
 * reports at {@code FinalizeRecording} (S29, FR-SESS-2) — the same boundary
 * posture as {@link SftpAuditPolicy}: the capability is allowlisted (it feeds
 * the audit row's {@code capabilities} column, whose DB CHECK would otherwise
 * roll back the whole finalize), direction is constrained, the target is
 * length-bounded, counters are clamped, and the batch is capped.
 */
public final class TunnelAuditPolicy {

	/** Max tunnel-audit entries accepted in one FinalizeRecording. */
	public static final int MAX_BATCH = 4096;

	/** Sentinel for a capability outside the forwarding vocabulary. */
	public static final String UNKNOWN = "unknown";

	private static final int MAX_TARGET = 512;
	private static final Set<String> CAPABILITIES = Set.of(Capabilities.PORT_FORWARD_LOCAL,
			Capabilities.PORT_FORWARD_REMOTE, Capabilities.X11);
	private static final Set<String> DIRECTIONS = Set.of("local", "remote", "x11");

	private TunnelAuditPolicy() {
	}

	public static TunnelAuditEntry normalize(TunnelAuditEntry entry) {
		String capability = entry.capability() == null ? "" : entry.capability().trim();
		capability = CAPABILITIES.contains(capability) ? capability : UNKNOWN;
		String direction = DIRECTIONS.contains(entry.direction()) ? entry.direction() : UNKNOWN;
		String target = entry.target() == null ? "" : entry.target();
		if (target.length() > MAX_TARGET) {
			target = target.substring(0, MAX_TARGET);
		}
		return new TunnelAuditEntry(capability, direction, target, Math.max(0, entry.bytesIn()),
				Math.max(0, entry.bytesOut()), Math.max(0, entry.durationSeconds()));
	}

	/**
	 * The audit action for a normalized entry. Only {@code .closed} kinds exist:
	 * tunnel audit lands at finalize time (the {@code sftp_audit} precedent), so a
	 * synthetic live-looking {@code .opened} row is never minted.
	 */
	public static String action(TunnelAuditEntry normalized) {
		return switch (normalized.capability()) {
			case Capabilities.X11 -> "x11_forward.closed";
			case Capabilities.PORT_FORWARD_LOCAL, Capabilities.PORT_FORWARD_REMOTE -> "port_forward.closed";
			default -> "tunnel.unknown";
		};
	}
}
