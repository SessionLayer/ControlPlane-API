package io.sessionlayer.controlplane.ca.sign;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.math.BigInteger;

/**
 * ECDSA signature normalization (FR-SIGN-2) and OpenSSH signature-blob
 * encoding. Backends return a raw signature in one of two shapes; both are
 * normalized to the {@code (r, s)} pair the OpenSSH format needs:
 *
 * <ul>
 * <li><b>DER</b> — {@code SEQUENCE { INTEGER r, INTEGER s }} (Java's
 * {@code SHA256withECDSA}, AWS KMS {@code ECDSA_SHA_256}).</li>
 * <li><b>P1363 / raw</b> — {@code r || s} fixed-width big-endian (Azure Key
 * Vault {@code ES256}).</li>
 * </ul>
 *
 * The OpenSSH ECDSA signature field is then:
 *
 * <pre>
 *   string   "ecdsa-sha2-nistp256"
 *   string   ( mpint r || mpint s )
 * </pre>
 */
public final class EcdsaSignatures {

	private EcdsaSignatures() {
	}

	/** A normalized ECDSA signature as its two integer components. */
	public record RS(BigInteger r, BigInteger s) {
	}

	/**
	 * Parse a DER {@code SEQUENCE { INTEGER r, INTEGER s }} into {@code (r, s)}. A
	 * minimal, strict, dependency-free DER reader: it validates the tags and
	 * lengths and rejects trailing garbage. The INTEGER content is a signed
	 * big-endian value (a leading {@code 0x00} keeps a high-bit value positive),
	 * which is exactly {@link BigInteger#BigInteger(byte[])}.
	 */
	public static RS fromDer(byte[] der) {
		DerReader seq = new DerReader(der);
		DerReader body = seq.readSequence();
		BigInteger r = body.readInteger();
		BigInteger s = body.readInteger();
		if (body.hasRemaining() || seq.hasRemaining()) {
			throw new IllegalArgumentException("trailing bytes in DER ECDSA signature");
		}
		requirePositive(r, s);
		return new RS(r, s);
	}

	/**
	 * Parse a P1363 / raw fixed-width {@code r || s} signature into {@code (r, s)}.
	 * The buffer is exactly {@code 2 * coordinateBytes} long; each half is an
	 * unsigned big-endian integer.
	 */
	public static RS fromP1363(byte[] raw, CaKeyType keyType) {
		int coordLen = keyType.coordinateBytes();
		if (raw.length != 2 * coordLen) {
			throw new IllegalArgumentException(
					"P1363 signature length " + raw.length + " != 2*" + coordLen + " for " + keyType.algorithmId());
		}
		byte[] rb = new byte[coordLen];
		byte[] sb = new byte[coordLen];
		System.arraycopy(raw, 0, rb, 0, coordLen);
		System.arraycopy(raw, coordLen, sb, 0, coordLen);
		BigInteger r = new BigInteger(1, rb); // unsigned
		BigInteger s = new BigInteger(1, sb);
		requirePositive(r, s);
		return new RS(r, s);
	}

	/**
	 * The OpenSSH ECDSA signature field content:
	 * {@code string(alg) || string(mpint r || mpint s)}.
	 */
	public static byte[] encodeSignatureBlob(CaKeyType keyType, RS rs) {
		byte[] inner = new SshWriter().writeMpint(rs.r()).writeMpint(rs.s()).toByteArray();
		return new SshWriter().writeString(keyType.keyTypeName()).writeString(inner).toByteArray();
	}

	/**
	 * DER-encode {@code (r, s)} as {@code SEQUENCE { INTEGER r, INTEGER s }} — the
	 * inverse of {@link #fromDer}, for feeding a JCA {@code Signature.verify} when
	 * verifying an OpenSSH-format ECDSA signature (whose {@code (r, s)} arrive as
	 * mpints, not DER). {@link BigInteger#toByteArray()} already yields the minimal
	 * signed big-endian form that is exactly a DER INTEGER's content.
	 */
	public static byte[] toDer(RS rs) {
		byte[] r = derInteger(rs.r());
		byte[] s = derInteger(rs.s());
		SshWriter seq = new SshWriter().writeByte(0x30);
		writeDerLength(seq, r.length + s.length);
		return seq.writeBytes(r).writeBytes(s).toByteArray();
	}

	private static byte[] derInteger(BigInteger value) {
		SshWriter w = new SshWriter().writeByte(0x02);
		byte[] content = value.toByteArray();
		writeDerLength(w, content.length);
		return w.writeBytes(content).toByteArray();
	}

	private static void writeDerLength(SshWriter w, int len) {
		if (len < 0x80) {
			w.writeByte(len);
		} else if (len < 0x100) {
			w.writeByte(0x81).writeByte(len);
		} else {
			w.writeByte(0x82).writeByte((len >>> 8) & 0xFF).writeByte(len & 0xFF);
		}
	}

	private static void requirePositive(BigInteger r, BigInteger s) {
		if (r.signum() <= 0 || s.signum() <= 0) {
			throw new IllegalArgumentException("ECDSA (r,s) must be positive");
		}
	}

	/**
	 * A tiny strict DER reader for the {@code SEQUENCE{INTEGER,INTEGER}} shape
	 * only.
	 */
	private static final class DerReader {
		private final byte[] buf;
		private int pos;
		private final int end;

		DerReader(byte[] buf) {
			this(buf, 0, buf.length);
		}

		DerReader(byte[] buf, int start, int end) {
			this.buf = buf;
			this.pos = start;
			this.end = end;
		}

		boolean hasRemaining() {
			return pos < end;
		}

		DerReader readSequence() {
			expectTag(0x30);
			int len = readLength();
			int start = pos;
			if (len > end - start) { // overflow-safe: end-start is a non-negative int
				throw new IllegalArgumentException("DER sequence length overruns buffer");
			}
			pos += len;
			return new DerReader(buf, start, start + len);
		}

		BigInteger readInteger() {
			expectTag(0x02);
			int len = readLength();
			if (len <= 0 || len > end - pos) { // overflow-safe
				throw new IllegalArgumentException("DER integer length invalid");
			}
			byte[] content = new byte[len];
			System.arraycopy(buf, pos, content, 0, len);
			pos += len;
			return new BigInteger(content); // signed big-endian per DER
		}

		private void expectTag(int tag) {
			if (pos >= end || (buf[pos] & 0xFF) != tag) {
				throw new IllegalArgumentException("expected DER tag 0x" + Integer.toHexString(tag));
			}
			pos++;
		}

		private int readLength() {
			if (pos >= end) {
				throw new IllegalArgumentException("truncated DER length");
			}
			int first = buf[pos++] & 0xFF;
			if (first < 0x80) {
				return first; // short form
			}
			int numBytes = first & 0x7F;
			if (numBytes == 0 || numBytes > 4 || pos + numBytes > end) {
				throw new IllegalArgumentException("unsupported DER length encoding");
			}
			int len = 0;
			for (int i = 0; i < numBytes; i++) {
				len = (len << 8) | (buf[pos++] & 0xFF);
			}
			if (len < 0) {
				throw new IllegalArgumentException("DER length overflow");
			}
			return len;
		}
	}
}
