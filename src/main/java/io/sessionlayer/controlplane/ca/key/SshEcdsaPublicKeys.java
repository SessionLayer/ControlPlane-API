package io.sessionlayer.controlplane.ca.key;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.wire.SshReader;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
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

	/**
	 * The OpenSSH public-key blob for an ECDSA key:
	 * {@code string(keytype) || curve+point}.
	 */
	public static byte[] encode(ECPublicKey publicKey, CaKeyType keyType) {
		return new SshWriter().writeString(keyType.keyTypeName()).writeBytes(encodeCurveAndPoint(publicKey, keyType))
				.toByteArray();
	}

	/**
	 * The type-specific ECDSA key fields used <b>inside a certificate</b>:
	 * {@code string(curve) || string(Q)} (the certificate's leading string is the
	 * cert-type name, which replaces the plain key-type name).
	 */
	public static byte[] encodeCurveAndPoint(ECPublicKey publicKey, CaKeyType keyType) {
		int coordLen = keyType.coordinateBytes();
		byte[] x = fixedWidth(publicKey.getW().getAffineX(), coordLen);
		byte[] y = fixedWidth(publicKey.getW().getAffineY(), coordLen);
		byte[] q = new byte[1 + x.length + y.length];
		q[0] = 0x04; // uncompressed point
		System.arraycopy(x, 0, q, 1, x.length);
		System.arraycopy(y, 0, q, 1 + x.length, y.length);
		return new SshWriter().writeString(keyType.curveName()).writeString(q).toByteArray();
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
	 * Parse an OpenSSH ECDSA public-key blob
	 * ({@code string(keytype) || string(curve)
	 * || string(Q)}) back into an {@link ECPublicKey}. Used to certify a
	 * Gateway-presented key and by tests to cross-check against {@code ssh-keygen}.
	 */
	public static ECPublicKey parse(byte[] blob) {
		try {
			SshReader reader = new SshReader(blob);
			CaKeyType keyType = CaKeyType.fromKeyTypeName(reader.readStringUtf8());
			// RFC 5656 §3.1: the [identifier] curve string MUST match the key type's curve
			// (F-SSHPUB-CURVE-1) — a mismatched label must be rejected, not ignored.
			String curve = reader.readStringUtf8();
			if (!keyType.curveName().equals(curve)) {
				throw new IllegalArgumentException(
						"curve '" + curve + "' does not match key type " + keyType.keyTypeName());
			}
			byte[] q = reader.readString();
			int coordLen = keyType.coordinateBytes();
			if (q.length != 1 + 2 * coordLen || q[0] != 0x04) {
				throw new IllegalArgumentException("expected uncompressed EC point (0x04||X||Y)");
			}
			BigInteger x = new BigInteger(1, Arrays.copyOfRange(q, 1, 1 + coordLen));
			BigInteger y = new BigInteger(1, Arrays.copyOfRange(q, 1 + coordLen, 1 + 2 * coordLen));
			AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
			params.init(new java.security.spec.ECGenParameterSpec(keyType.jcaCurve()));
			ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
			ECPoint point = new ECPoint(x, y);
			// Validate the point is actually ON the named curve (JCA does not check this on
			// import): reject point-at-infinity, out-of-range coords, and y^2 != x^3+ax+b.
			requireOnCurve(point, spec);
			return (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
		} catch (Exception e) {
			throw new IllegalArgumentException("failed to parse SSH ECDSA public key", e);
		}
	}

	/**
	 * Reject a point not on the curve (defense at the presented-key trust
	 * boundary).
	 */
	static void requireOnCurve(ECPoint point, ECParameterSpec spec) {
		if (point.equals(ECPoint.POINT_INFINITY)) {
			throw new IllegalArgumentException("EC point is the point at infinity");
		}
		java.security.spec.EllipticCurve curve = spec.getCurve();
		BigInteger p = ((java.security.spec.ECFieldFp) curve.getField()).getP();
		BigInteger x = point.getAffineX();
		BigInteger y = point.getAffineY();
		if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
			throw new IllegalArgumentException("EC coordinate out of field range");
		}
		BigInteger lhs = y.modPow(BigInteger.TWO, p);
		BigInteger rhs = x.modPow(BigInteger.valueOf(3), p).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
		if (!lhs.equals(rhs)) {
			throw new IllegalArgumentException("EC point is not on the curve");
		}
	}

	/** Parse an OpenSSH {@code "<type> <base64> [comment]"} public-key line. */
	public static ECPublicKey parseAuthorizedKey(String line) {
		String[] parts = line.trim().split("\\s+");
		if (parts.length < 2) {
			throw new IllegalArgumentException("not an OpenSSH public-key line");
		}
		return parse(Base64.getDecoder().decode(parts[1]));
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
