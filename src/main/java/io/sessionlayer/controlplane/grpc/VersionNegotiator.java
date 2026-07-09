package io.sessionlayer.controlplane.grpc;

import io.sessionlayer.controlplane.grpc.v1.ProtocolVersion;
import java.util.Optional;

/**
 * Pure, order-independent resolution of the highest protocol version supported
 * by both peers.
 *
 * <p>
 * Per {@code contracts/proto/.../handshake.proto} and {@code VERSIONING.md} §3:
 *
 * <pre>
 *   selected = min(clientMax, serverMax),
 *   valid iff min(clientMax, serverMax) &gt;= max(clientMin, serverMin).
 * </pre>
 *
 * <p>
 * The result is a deterministic, side-effect-free function of the two ranges,
 * so any CP replica answers identically (the same determinism property the RBAC
 * engine relies on).
 */
public final class VersionNegotiator {

	private VersionNegotiator() {
	}

	/**
	 * Resolve the highest common protocol version, or empty if the ranges do not
	 * overlap.
	 *
	 * @return the selected version (the highest common one), or
	 *         {@link Optional#empty()} when the peers share no common version
	 */
	public static Optional<ProtocolVersion> highestCommon(ProtocolVersion clientMin, ProtocolVersion clientMax,
			ProtocolVersion serverMin, ProtocolVersion serverMax) {
		ProtocolVersion low = higher(clientMin, serverMin);
		ProtocolVersion high = lower(clientMax, serverMax);
		return compare(low, high) <= 0 ? Optional.of(high) : Optional.empty();
	}

	/**
	 * Compare by (major, minor); return value follows {@link Integer#compare}
	 * conventions.
	 */
	public static int compare(ProtocolVersion a, ProtocolVersion b) {
		// major/minor are proto uint32; treat them as unsigned non-negative version
		// components.
		int byMajor = Integer.compareUnsigned(a.getMajor(), b.getMajor());
		return byMajor != 0 ? byMajor : Integer.compareUnsigned(a.getMinor(), b.getMinor());
	}

	private static ProtocolVersion higher(ProtocolVersion a, ProtocolVersion b) {
		return compare(a, b) >= 0 ? a : b;
	}

	private static ProtocolVersion lower(ProtocolVersion a, ProtocolVersion b) {
		return compare(a, b) <= 0 ? a : b;
	}
}
