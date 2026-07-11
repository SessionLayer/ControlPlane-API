package io.sessionlayer.controlplane.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Small secret-handling primitives shared by the authentication surface (Design
 * §2.5): SHA-256 hashing (what we store instead of raw OTP/token/jti values),
 * constant-time comparison, and high-entropy token/code generation. No raw
 * secret is ever persisted — callers store {@link #sha256Hex} outputs.
 */
public final class Secrets {

	private static final SecureRandom RANDOM = new SecureRandom();
	private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

	private Secrets() {
	}

	/** Hex SHA-256 of a value (the at-rest representation of a secret). */
	public static String sha256Hex(String value) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
			StringBuilder hex = new StringBuilder(digest.length * 2);
			for (byte b : digest) {
				hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
			}
			return hex.toString();
		} catch (Exception e) {
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}

	/** Constant-time equality of two strings (no early-exit on the first diff). */
	public static boolean constantTimeEquals(String a, String b) {
		if (a == null || b == null) {
			return false;
		}
		return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
	}

	/** A URL-safe, unpadded base64 random token of {@code bytes} entropy. */
	public static String randomToken(int bytes) {
		byte[] raw = new byte[bytes];
		RANDOM.nextBytes(raw);
		return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
	}

	/** An uppercase base32 (A-Z,2-7) code — human-typeable for OTP delivery. */
	public static String randomBase32(int bytes) {
		byte[] raw = new byte[bytes];
		RANDOM.nextBytes(raw);
		return base32(raw);
	}

	/** A short, grouped user code for the device-flow verification page. */
	public static String randomUserCode() {
		byte[] raw = new byte[5];
		RANDOM.nextBytes(raw);
		String code = base32(raw); // 8 chars
		return code.substring(0, 4) + "-" + code.substring(4, 8);
	}

	private static String base32(byte[] data) {
		StringBuilder out = new StringBuilder();
		int buffer = 0;
		int bits = 0;
		for (byte b : data) {
			buffer = (buffer << 8) | (b & 0xFF);
			bits += 8;
			while (bits >= 5) {
				out.append(BASE32[(buffer >> (bits - 5)) & 0x1F]);
				bits -= 5;
			}
		}
		if (bits > 0) {
			out.append(BASE32[(buffer << (5 - bits)) & 0x1F]);
		}
		return out.toString();
	}
}
