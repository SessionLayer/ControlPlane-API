package io.sessionlayer.controlplane.ca.backend.local;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A key-encryption key (KEK) used to envelope-encrypt a local CA private key
 * (FR-CA-8, Design §14). AES-256-GCM: the CA private key never touches disk in
 * the clear, and the KEK itself is sourced from the environment (never the DB,
 * never hardcoded — {@link KekProvider}), so a datastore-only compromise yields
 * ciphertext it cannot unwrap.
 *
 * <p>
 * The KEK byte material is held in a {@code byte[]} that {@link #destroy()}
 * zeroizes; plaintext buffers produced by {@link #unwrap} are the caller's to
 * zeroize after use. Not thread-safe for {@link #destroy()}.
 */
public final class Kek {

	private static final int GCM_TAG_BITS = 128;
	private static final int IV_BYTES = 12;
	private static final SecureRandom RANDOM = new SecureRandom();

	private final byte[] keyBytes;

	/**
	 * @param keyBytes
	 *            32 bytes (AES-256). The array is copied defensively.
	 */
	public Kek(byte[] keyBytes) {
		if (keyBytes.length != 32) {
			throw new IllegalArgumentException("KEK must be 32 bytes (AES-256), got " + keyBytes.length);
		}
		this.keyBytes = keyBytes.clone();
	}

	/**
	 * A wrapped blob: the GCM nonce and the ciphertext (with the auth tag
	 * appended).
	 */
	public record Wrapped(byte[] iv, byte[] ciphertext) {
	}

	/**
	 * Envelope-encrypt {@code plaintext} under this KEK (fresh random IV).
	 * {@code aad} (the associated data — e.g. the CA config id + key type + KEK
	 * reference) is authenticated but not encrypted, binding the ciphertext to its
	 * row so a DB-write attacker cannot lift a valid blob into a different CA's row
	 * (cross-CA substitution). {@code unwrap} MUST pass the identical {@code aad}.
	 */
	public Wrapped wrap(byte[] plaintext, byte[] aad) {
		try {
			byte[] iv = new byte[IV_BYTES];
			RANDOM.nextBytes(iv);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
					new GCMParameterSpec(GCM_TAG_BITS, iv));
			cipher.updateAAD(aad);
			return new Wrapped(iv, cipher.doFinal(plaintext));
		} catch (Exception e) {
			throw new IllegalStateException("KEK wrap failed", e);
		}
	}

	/**
	 * Decrypt a wrapped blob, authenticating {@code aad}. Fails closed (throws) on
	 * any KEK / ciphertext / <b>context</b> mismatch. The caller MUST zeroize the
	 * returned plaintext after use.
	 */
	public byte[] unwrap(byte[] iv, byte[] ciphertext, byte[] aad) {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
					new GCMParameterSpec(GCM_TAG_BITS, iv));
			cipher.updateAAD(aad);
			return cipher.doFinal(ciphertext);
		} catch (Exception e) {
			throw new IllegalStateException("KEK unwrap failed (wrong KEK, tampered ciphertext, or wrong CA context)",
					e);
		}
	}

	/** Zeroize the KEK material. */
	public void destroy() {
		Arrays.fill(keyBytes, (byte) 0);
	}
}
