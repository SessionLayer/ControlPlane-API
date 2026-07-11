package io.sessionlayer.controlplane.gateway;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Mint/validate helper for single-use bearer tokens (the reusable
 * {@code JoinMethod} token shape agents will reuse in S12). A token is a
 * 256-bit cryptographically-random value; only its <b>SHA-256 hash</b> is ever
 * persisted (mirrors {@code join_token}/{@code otp}), so a datastore compromise
 * yields hashes it cannot present. The raw value is returned to the minting
 * caller exactly once and never stored.
 */
public final class SingleUseTokens {

	private static final SecureRandom RANDOM = new SecureRandom();
	private static final int TOKEN_BYTES = 32; // 256 bits

	private SingleUseTokens() {
	}

	/** A freshly minted token: the raw bearer value and its stored hash. */
	public record Minted(String raw, String hash) {
	}

	/** Mint a new random token and its hash. */
	public static Minted mint() {
		byte[] material = new byte[TOKEN_BYTES];
		RANDOM.nextBytes(material);
		String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(material);
		return new Minted(raw, hash(raw));
	}

	/** The SHA-256 hash (lowercase hex) of a raw token — the lookup/storage key. */
	public static String hash(String rawToken) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256")
					.digest(rawToken.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		} catch (Exception e) {
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}
}
