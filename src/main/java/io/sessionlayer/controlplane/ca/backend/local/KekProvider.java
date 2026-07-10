package io.sessionlayer.controlplane.ca.backend.local;

import java.security.MessageDigest;
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
 * a durable operator secret, not generated per boot.
 *
 * <p>
 * <b>Fail-closed default (F-ca-kek-default-1):</b> the built-in dev/test KEK is
 * a public constant, so wrapping a CA key under it is a no-op against a DB-only
 * compromise. The provider therefore <b>refuses to start</b> when the dev
 * default is in effect unless {@code allowDevDefault} is explicitly set
 * ({@code sessionlayer.ca.local.allow-dev-kek=true}) — a dev/test-only opt-in
 * that production must never set. The dev-default check compares the <b>decoded
 * bytes</b> (a re-encoding cannot smuggle the insecure key past it).
 */
public final class KekProvider {

	/** A well-known dev/test KEK (32 bytes, base64). NEVER for production. */
	public static final String DEV_DEFAULT_KEK_BASE64 = "c2Vzc2lvbmxheWVyRGV2S2VrMDEyMzQ1Njc4OUFCQ0Q=";
	private static final byte[] DEV_DEFAULT_KEK_BYTES = Base64.getDecoder().decode(DEV_DEFAULT_KEK_BASE64);

	private final byte[] kekBytes;
	private final String reference;
	private final boolean devDefault;

	public KekProvider(String kekBase64, String reference, boolean allowDevDefault) {
		boolean unset = (kekBase64 == null || kekBase64.isBlank());
		byte[] decoded = Base64.getDecoder().decode(unset ? DEV_DEFAULT_KEK_BASE64 : kekBase64);
		if (decoded.length != 32) {
			throw new IllegalArgumentException("KEK must decode to 32 bytes (AES-256), got " + decoded.length);
		}
		// Compare decoded BYTES (constant-time), not the base64 string, so a
		// re-encoding
		// of the dev key is still detected.
		this.devDefault = MessageDigest.isEqual(decoded, DEV_DEFAULT_KEK_BYTES);
		if (this.devDefault && !allowDevDefault) {
			throw new IllegalStateException(
					"refusing to start: the local CA KEK is the built-in DEV default (a public constant). "
							+ "Set sessionlayer.ca.local.kek-base64 to a real 32-byte base64 KEK, or set "
							+ "sessionlayer.ca.local.allow-dev-kek=true for dev/test ONLY (never in production).");
		}
		this.kekBytes = decoded;
		// The default reference names what is actually read (the property), not a
		// misleading env var; the dev default is labelled insecure.
		this.reference = (reference != null && !reference.isBlank())
				? reference
				: (this.devDefault ? "dev-default:insecure" : "config:sessionlayer.ca.local.kek-base64");
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
