package io.sessionlayer.controlplane.ca.backend.local;

import io.sessionlayer.controlplane.ca.CaKeyType;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Generates and loads a local CA ECDSA key, envelope-encrypted with a
 * {@link Kek} (FR-CA-8). On generation the plaintext PKCS#8 private key buffer
 * is <b>zeroized immediately after wrapping</b>; on load it is zeroized
 * immediately after import — the plaintext key material exists only transiently
 * in-process (§5.3). The public key is stored as X.509 (public material) so it
 * can be reconstructed without the private key.
 */
public final class LocalCaKeyStore {

	private final SecureRandom random;

	public LocalCaKeyStore() {
		this(new SecureRandom());
	}

	public LocalCaKeyStore(SecureRandom random) {
		this.random = random;
	}

	/** A freshly generated CA key: the KEK-wrapped private key + the public key. */
	public record GeneratedKey(Kek.Wrapped wrapped, byte[] publicKeyX509, ECPublicKey publicKey) {
	}

	/**
	 * Generate a new ECDSA CA key of the given type and wrap the private key under
	 * {@code kek}, binding it to {@code aad} (the CA row context). The plaintext
	 * PKCS#8 buffer is zeroized and the transient JCA private key is best-effort
	 * destroyed immediately after wrapping.
	 */
	public GeneratedKey generate(CaKeyType keyType, Kek kek, byte[] aad) {
		KeyPair keyPair = generateKeyPair(keyType);
		byte[] pkcs8 = keyPair.getPrivate().getEncoded();
		try {
			Kek.Wrapped wrapped = kek.wrap(pkcs8, aad);
			return new GeneratedKey(wrapped, keyPair.getPublic().getEncoded(), (ECPublicKey) keyPair.getPublic());
		} finally {
			Arrays.fill(pkcs8, (byte) 0); // zeroize plaintext private key buffer
			destroyQuietly(keyPair.getPrivate()); // best-effort: BigInteger copies are un-zeroable, GC-only
		}
	}

	/** Unwrap and import a previously generated CA key into a signing backend. */
	public LocalCaBackend load(CaKeyType keyType, Kek kek, Kek.Wrapped wrapped, byte[] publicKeyX509, byte[] aad) {
		byte[] pkcs8 = kek.unwrap(wrapped.iv(), wrapped.ciphertext(), aad);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("EC");
			PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
			ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyX509));
			return new LocalCaBackend(keyType, privateKey, publicKey);
		} catch (Exception e) {
			throw new IllegalStateException("failed to load local CA key", e);
		} finally {
			Arrays.fill(pkcs8, (byte) 0); // zeroize plaintext private key buffer
		}
	}

	private static void destroyQuietly(PrivateKey key) {
		try {
			if (key instanceof javax.security.auth.Destroyable d && !d.isDestroyed()) {
				d.destroy();
			}
		} catch (Exception ignored) {
			// Most JCA private keys throw DestroyFailedException (no-op destroy) — the
			// scalar lives in an immutable BigInteger and is reclaimed only by GC; this is
			// inherent to a local software signer (why production SHOULD use
			// KMS/KeyVault/Vault).
		}
	}

	private KeyPair generateKeyPair(CaKeyType keyType) {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec(keyType.jcaCurve()), random);
			return generator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException("failed to generate local CA key for " + keyType.algorithmId(), e);
		}
	}
}
