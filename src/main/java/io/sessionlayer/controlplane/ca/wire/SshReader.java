package io.sessionlayer.controlplane.ca.wire;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * SSH wire-format decoder (RFC 4251 §5) — the inverse of {@link SshWriter}.
 * Used to parse a public-key blob (e.g. to read a signature type) and by tests
 * to cross-check the certificate encoding. Bounds-checked: a truncated or
 * over-long length raises rather than reading out of range.
 */
public final class SshReader {

	private final byte[] buf;
	private int pos;

	public SshReader(byte[] buf) {
		this.buf = buf;
	}

	public boolean hasRemaining() {
		return pos < buf.length;
	}

	public int remaining() {
		return buf.length - pos;
	}

	/**
	 * The current read offset (e.g. to slice the to-be-signed prefix of a cert).
	 */
	public int position() {
		return pos;
	}

	public long readUint32() {
		require(4);
		long v = ((buf[pos] & 0xFFL) << 24) | ((buf[pos + 1] & 0xFFL) << 16) | ((buf[pos + 2] & 0xFFL) << 8)
				| (buf[pos + 3] & 0xFFL);
		pos += 4;
		return v;
	}

	public long readUint64() {
		long hi = readUint32();
		long lo = readUint32();
		return (hi << 32) | lo;
	}

	public byte[] readString() {
		long len = readUint32();
		if (len < 0 || len > remaining()) {
			throw new IllegalArgumentException("ssh string length " + len + " exceeds remaining " + remaining());
		}
		byte[] s = Arrays.copyOfRange(buf, pos, pos + (int) len);
		pos += (int) len;
		return s;
	}

	public String readStringUtf8() {
		return new String(readString(), StandardCharsets.UTF_8);
	}

	public BigInteger readMpint() {
		byte[] s = readString();
		if (s.length == 0) {
			return BigInteger.ZERO;
		}
		return new BigInteger(s);
	}

	private void require(int n) {
		if (remaining() < n) {
			throw new IllegalArgumentException("need " + n + " bytes, have " + remaining());
		}
	}
}
