package io.sessionlayer.controlplane.ca.wire;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * SSH wire-format encoder (RFC 4251 §5). The primitive types the OpenSSH
 * certificate format is built from:
 *
 * <ul>
 * <li>{@code byte} / raw bytes,</li>
 * <li>{@code uint32} — 4-byte big-endian,</li>
 * <li>{@code uint64} — 8-byte big-endian,</li>
 * <li>{@code boolean} — a single 0/1 byte,</li>
 * <li>{@code string} — a {@code uint32} length prefix followed by that many
 * bytes (this is the load-bearing one — the certificate is a nest of
 * length-prefixed strings, and the "double length prefix" for value-carrying
 * critical options is just a {@code string} whose content is itself a
 * {@code string}),</li>
 * <li>{@code mpint} — a multiple-precision integer as a two's-complement
 * big-endian {@code string}, minimal length, a leading {@code 0x00} when the
 * high bit would otherwise make it negative; zero is the empty string.</li>
 * </ul>
 *
 * Instances are mutable, not thread-safe, and chainable.
 */
public final class SshWriter {

	private final ByteArrayOutputStream out = new ByteArrayOutputStream();

	public SshWriter writeByte(int b) {
		out.write(b & 0xFF);
		return this;
	}

	public SshWriter writeBytes(byte[] bytes) {
		out.write(bytes, 0, bytes.length);
		return this;
	}

	public SshWriter writeBoolean(boolean value) {
		return writeByte(value ? 1 : 0);
	}

	public SshWriter writeUint32(long value) {
		if (value < 0 || value > 0xFFFFFFFFL) {
			throw new IllegalArgumentException("uint32 out of range: " + value);
		}
		out.write((int) ((value >>> 24) & 0xFF));
		out.write((int) ((value >>> 16) & 0xFF));
		out.write((int) ((value >>> 8) & 0xFF));
		out.write((int) (value & 0xFF));
		return this;
	}

	public SshWriter writeUint64(long value) {
		writeUint32((value >>> 32) & 0xFFFFFFFFL);
		writeUint32(value & 0xFFFFFFFFL);
		return this;
	}

	/** A {@code string}: {@code uint32} length prefix + the raw bytes. */
	public SshWriter writeString(byte[] value) {
		writeUint32(value.length);
		return writeBytes(value);
	}

	/** A {@code string} of UTF-8 encoded text. */
	public SshWriter writeString(String value) {
		return writeString(value.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * An {@code mpint} (RFC 4251). Two's-complement big-endian, minimal length,
	 * with a leading {@code 0x00} when the top bit is set (to stay positive); zero
	 * encodes as an empty string. {@link BigInteger#toByteArray()} already yields
	 * exactly this two's-complement minimal form for a positive value, so it is
	 * used directly (with the zero special-case).
	 */
	public SshWriter writeMpint(BigInteger value) {
		if (value.signum() == 0) {
			return writeString(new byte[0]);
		}
		if (value.signum() < 0) {
			throw new IllegalArgumentException("negative mpint not expected for SSH signatures/keys");
		}
		return writeString(value.toByteArray());
	}

	public byte[] toByteArray() {
		return out.toByteArray();
	}
}
