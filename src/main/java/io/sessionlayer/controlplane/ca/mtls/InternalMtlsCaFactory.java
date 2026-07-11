package io.sessionlayer.controlplane.ca.mtls;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.backend.local.Kek;
import io.sessionlayer.controlplane.ca.backend.local.KekProvider;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Creates and loads the internal mTLS CA (X.509, ECDSA P-256) — the trust
 * anchor for the CP↔Gateway plane (VERSIONING.md §7). Mirrors
 * {@code LocalCaFactory} (the SSH local CA) but produces an X.509 self-signed
 * CA certificate rather than an SSH signer. The CA private key is
 * envelope-encrypted under the operator KEK (FR-CA-8) with the identical
 * row-binding AAD scheme, so a wrapped blob cannot be lifted into a different
 * CA's row (cross-CA substitution). Only the local backend is implemented; a
 * cloud X.509 backend plugs in behind {@link X509CaBackend}.
 */
@Component
public class InternalMtlsCaFactory {

	private static final Logger LOG = LoggerFactory.getLogger(InternalMtlsCaFactory.class);

	/** The internal mTLS CA is ECDSA P-256 (platform default, D6). */
	private static final CaKeyType KEY_TYPE = CaKeyType.ECDSA_NISTP256;
	/** {@code config.ca_config.ca_kind} for the internal mTLS CA (V14). */
	public static final String CA_KIND = "mtls";
	/** The default CA config name for the internal mTLS CA. */
	public static final String DEFAULT_NAME = "mtls-ca";
	private static final String CA_COMMON_NAME = "SessionLayer Internal mTLS CA";
	/** CA certificate lifetime — long-lived (rotation is a later concern). */
	private static final Duration CA_VALIDITY = Duration.ofDays(3650);

	private final KekProvider kekProvider;
	private final SecureRandom random = new SecureRandom();

	public InternalMtlsCaFactory(KekProvider kekProvider) {
		this.kekProvider = kekProvider;
	}

	/** A generated internal mTLS CA: its config row and KEK-wrapped material. */
	public record Provisioned(CaConfig config, CaKeyMaterial material) {
	}

	/**
	 * Generate a new internal mTLS CA (self-signed X.509 + KEK-wrapped key). The
	 * plaintext PKCS#8 buffer is zeroized immediately after wrapping.
	 */
	public Provisioned create(String name, String rotationState) {
		warn();
		UUID configId = Uuids.v7();
		KeyPair keyPair = generateKeyPair();
		Instant now = Instant.now();
		X509Certificate caCertificate = X509Certificates.selfSignCa(CA_COMMON_NAME, keyPair.getPublic(),
				keyPair.getPrivate(), newSerial(), now.minus(Duration.ofMinutes(5)), now.plus(CA_VALIDITY));

		byte[] aad = aad(configId, KEY_TYPE.keyTypeName(), kekProvider.reference());
		byte[] pkcs8 = keyPair.getPrivate().getEncoded();
		Kek kek = kekProvider.newKek();
		Kek.Wrapped wrapped;
		try {
			wrapped = kek.wrap(pkcs8, aad);
		} finally {
			Arrays.fill(pkcs8, (byte) 0); // zeroize plaintext private key buffer
			kek.destroy();
		}

		CaConfig config = new CaConfig(configId, name, CA_KIND, "local", "local:" + configId, KEY_TYPE.algorithmId(),
				rotationState, "default", null, null, null);
		CaKeyMaterial material = CaKeyMaterial.create(configId, name, kekProvider.reference(), wrapped.ciphertext(),
				wrapped.iv(), keyPair.getPublic().getEncoded(), KEY_TYPE.keyTypeName(), der(caCertificate));
		return new Provisioned(config, material);
	}

	/**
	 * Load a persisted internal mTLS CA into a signing backend (unwraps
	 * transiently).
	 */
	public LocalX509CaBackend load(CaConfig config, CaKeyMaterial material) {
		warn();
		if (material.caCertificate() == null) {
			throw new IllegalStateException("mtls CA row " + config.name() + " has no ca_certificate (corrupt)");
		}
		byte[] aad = aad(material.caConfigId(), material.keyType(), material.kekReference());
		Kek kek = kekProvider.newKek();
		byte[] pkcs8 = null;
		try {
			pkcs8 = kek.unwrap(material.iv(), material.wrappedKey(), aad);
			PrivateKey caKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
			X509Certificate caCert = X509Certificates.parse(material.caCertificate());
			return new LocalX509CaBackend(caCert, caKey);
		} catch (Exception e) {
			throw new IllegalStateException("failed to load internal mTLS CA " + config.name(), e);
		} finally {
			if (pkcs8 != null) {
				Arrays.fill(pkcs8, (byte) 0); // zeroize plaintext private key buffer
			}
			kek.destroy();
		}
	}

	private KeyPair generateKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec(KEY_TYPE.jcaCurve()), random);
			return generator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException("failed to generate internal mTLS CA key", e);
		}
	}

	private BigInteger newSerial() {
		return new BigInteger(159, random).add(BigInteger.ONE); // positive, non-zero
	}

	private static byte[] der(X509Certificate certificate) {
		try {
			return certificate.getEncoded();
		} catch (Exception e) {
			throw new IllegalStateException("failed to encode internal mTLS CA certificate", e);
		}
	}

	/**
	 * The AAD binding a wrapped CA key to its row ({@code caConfigId | keyType |
	 * kekReference}) — identical on wrap and unwrap (same scheme as the SSH local
	 * CA), so a wrapped blob cannot be substituted across rows.
	 */
	private static byte[] aad(UUID caConfigId, String keyTypeName, String kekReference) {
		return (caConfigId + "|" + keyTypeName + "|" + kekReference).getBytes(StandardCharsets.UTF_8);
	}

	private void warn() {
		if (kekProvider.isDevDefault()) {
			LOG.warn("SECURITY: the local CA KEK is the built-in DEV default (public constant) — set a real KEK "
					+ "(sessionlayer.ca.local.kek-base64 / env). This is dev/test ONLY.");
		}
		LOG.warn("local X.509 backend in use for the internal mTLS CA; production SHOULD use a cloud X.509 CA so the "
				+ "CA private key is never in-process (FR-CA-8, Design §14).");
	}
}
