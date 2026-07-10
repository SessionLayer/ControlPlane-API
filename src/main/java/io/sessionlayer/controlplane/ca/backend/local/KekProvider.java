package io.sessionlayer.controlplane.ca.backend.local;

import java.util.Base64;

/**
 * Sources the local-CA KEK (FR-CA-8): the 32-byte key-encryption key comes from
 * operator configuration / the environment, <b>never hardcoded and never from
 * the database</b>. A fresh {@link Kek} is minted per operation and the caller
 * {@link Kek#destroy() destroys} it after use (transient plaintext, §5.3).
 *
 * <p>
 * The KEK must be <b>stable across restarts</b> for cold start to be idempotent
 * (the same KEK must unwrap a previously-wrapped CA key), so it is sourced from
 * a durable operator secret, not generated per boot. A dev/test default is
 * provided with a loud warning; production MUST override it.
 */
public final class KekProvider {

	/** A well-known dev/test KEK (32 bytes, base64). NEVER for production. */
	public static final String DEV_DEFAULT_KEK_BASE64 = "c2Vzc2lvbmxheWVyRGV2S2VrMDEyMzQ1Njc4OUFCQ0Q=";

	private final byte[] kekBytes;
	private final String reference;
	private final boolean devDefault;

	public KekProvider(String kekBase64, String reference) {
		String source = (kekBase64 == null || kekBase64.isBlank()) ? DEV_DEFAULT_KEK_BASE64 : kekBase64;
		this.devDefault = source.equals(DEV_DEFAULT_KEK_BASE64);
		byte[] decoded = Base64.getDecoder().decode(source);
		if (decoded.length != 32) {
			throw new IllegalArgumentException("KEK must decode to 32 bytes (AES-256), got " + decoded.length);
		}
		this.kekBytes = decoded;
		this.reference = (reference == null || reference.isBlank()) ? "env:SESSIONLAYER_CP_KEK" : reference;
	}

	/** A fresh {@link Kek}; the caller MUST {@link Kek#destroy()} it after use. */
	public Kek newKek() {
		return new Kek(kekBytes);
	}

	/**
	 * The opaque reference recorded alongside wrapped material (never the KEK
	 * itself).
	 */
	public String reference() {
		return reference;
	}

	/** True when the insecure dev/test default KEK is in use (warn loudly). */
	public boolean isDevDefault() {
		return devDefault;
	}
}
