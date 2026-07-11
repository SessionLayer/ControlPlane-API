package io.sessionlayer.controlplane.protocol;

import io.sessionlayer.controlplane.grpc.v1.ProtocolVersion;

/**
 * Single source of truth for the CP&lt;-&gt;Gateway gRPC protocol version this
 * build speaks.
 *
 * <p>
 * Consumed by both the gRPC {@code Handshake} server and the REST
 * {@code /v1/version} endpoint so the two surfaces can never disagree. Per
 * {@code contracts/VERSIONING.md} §6 the Session Four range is {@code [1.0,
 * 1.1]}: Session Four added three additive services to the plane
 * ({@code GatewayIdentity.EnrollGateway/RenewGatewayIdentity} and
 * {@code SessionSigning.SignSessionCertificate}), which is a MINOR bump, so
 * this build advertises {@code protocol_max = 1.1} while keeping
 * {@code protocol_min
 * = 1.0} — the N-1 window (VERSIONING.md §4) that lets a 1.1 CP still negotiate
 * 1.0 with a Gateway that has not upgraded.
 */
public final class ProtocolVersions {

	public static final int MAJOR = 1;
	public static final int MINOR = 1;

	/** The highest protocol version this build speaks (1.1). */
	public static final ProtocolVersion CURRENT = of(MAJOR, MINOR);

	/**
	 * Inclusive lowest supported version — held at the previous minor (1.0) to
	 * honour the N-1 window (VERSIONING.md §4): a 1.1 CP still negotiates 1.0 with
	 * a peer that has not upgraded.
	 */
	public static final ProtocolVersion SUPPORTED_MIN = of(MAJOR, MINOR - 1);

	/** Inclusive highest supported version (1.1). */
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
