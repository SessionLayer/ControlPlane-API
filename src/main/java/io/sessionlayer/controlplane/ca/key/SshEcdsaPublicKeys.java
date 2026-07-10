package io.sessionlayer.controlplane.ca.key;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/**
 * Encodes an ECDSA {@link ECPublicKey} into the OpenSSH public-key blob used
 * both as the certified key's fields inside a certificate and as the CA's
 * "signature key" field. The blob is:
 *
 * <pre>
 *   string   key-type name   (e.g. "ecdsa-sha2-nistp256")
 *   string   curve name      (e.g. "nistp256")
 *   string   Q               (uncompressed EC point: 0x04 || X || Y, each coord fixed-width)
 * </pre>
 */
public final class SshEcdsaPublicKeys {

	private SshEcdsaPublicKeys() {
	}

	/** The OpenSSH public-key blob for an ECDSA key of the given type. */
	public static byte[] encode(ECPublicKey publicKey, CaKeyType keyType) {
		int coordLen = keyType.coordinateBytes();
		byte[] x = fixedWidth(publicKey.getW().getAffineX(), coordLen);
		byte[] y = fixedWidth(publicKey.getW().getAffineY(), coordLen);
		byte[] q = new byte[1 + x.length + y.length];
		q[0] = 0x04; // uncompressed point
		System.arraycopy(x, 0, q, 1, x.length);
		System.arraycopy(y, 0, q, 1 + x.length, y.length);
		return new SshWriter().writeString(keyType.keyTypeName()).writeString(keyType.curveName()).writeString(q)
				.toByteArray();
	}

	/**
	 * The {@code authorized_keys}/{@code TrustedUserCAKeys} single-line form:
	 * {@code "<key-type> <base64(blob)> <comment>"}.
	 */
	public static String toAuthorizedKey(ECPublicKey publicKey, CaKeyType keyType, String comment) {
		String b64 = Base64.getEncoder().encodeToString(encode(publicKey, keyType));
		return keyType.keyTypeName() + " " + b64 + (comment == null || comment.isBlank() ? "" : " " + comment);
	}

	/**
	 * Big-endian fixed-width encoding of a non-negative integer: strips
	 * {@link BigInteger#toByteArray()}'s sign byte and left-pads with zeros to
	 * {@code length}. Rejects a value too wide for the coordinate size.
	 */
	static byte[] fixedWidth(BigInteger value, int length) {
		byte[] raw = value.toByteArray();
		// Drop a leading 0x00 sign byte if present.
		int start = 0;
		if (raw.length > 1 && raw[0] == 0x00) {
			start = 1;
		}
		int len = raw.length - start;
		if (len > length) {
			throw new IllegalArgumentException("coordinate too wide (" + len + " > " + length + " bytes)");
		}
		byte[] out = new byte[length];
		System.arraycopy(raw, start, out, length - len, len);
		return out;
	}
}
