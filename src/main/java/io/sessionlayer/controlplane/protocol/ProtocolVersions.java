package io.sessionlayer.controlplane.protocol;

import io.sessionlayer.controlplane.grpc.v1.ProtocolVersion;

/**
 * Single source of truth for the CP&lt;-&gt;Gateway gRPC protocol version this
 * build speaks.
 *
 * <p>
 * Consumed by both the gRPC {@code Handshake} server and the REST
 * {@code /v1/version} endpoint so the two surfaces can never disagree. Per
 * {@code contracts/VERSIONING.md} §6 the Session One baseline is a single point
 * range {@code protocol_min == protocol_max == 1.0}.
 */
public final class ProtocolVersions {

	public static final int MAJOR = 1;
	public static final int MINOR = 0;

	/** The protocol version this build speaks (1.0). */
	public static final ProtocolVersion CURRENT = of(MAJOR, MINOR);

	/**
	 * Inclusive lowest supported version. Session One: the range is the single
	 * point [1.0, 1.0].
	 */
	public static final ProtocolVersion SUPPORTED_MIN = CURRENT;

	/**
	 * Inclusive highest supported version. Session One: the range is the single
	 * point [1.0, 1.0].
	 */
	public static final ProtocolVersion SUPPORTED_MAX = CURRENT;

	private ProtocolVersions() {
	}

	/** Build a {@link ProtocolVersion} from major/minor components. */
	public static ProtocolVersion of(int major, int minor) {
		return ProtocolVersion.newBuilder().setMajor(major).setMinor(minor).build();
	}

	/**
	 * Render a version as the {@code major.minor} string used on the REST surface,
	 * e.g. "1.0".
	 */
	public static String display(ProtocolVersion version) {
		// major/minor are proto uint32; render unsigned so out-of-int-range values
		// from a hostile peer show correctly in diagnostics rather than as negatives.
		return Integer.toUnsignedString(version.getMajor()) + "." + Integer.toUnsignedString(version.getMinor());
	}
}
