package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.backend.local.Kek;
import io.sessionlayer.controlplane.ca.backend.local.KekProvider;
import io.sessionlayer.controlplane.ca.backend.local.LocalCaBackend;
import io.sessionlayer.controlplane.ca.backend.local.LocalCaKeyStore;
import io.sessionlayer.controlplane.ca.cert.OpenSshCertificateAssembler;
import io.sessionlayer.controlplane.data.Uuids;
import io.sessionlayer.controlplane.data.config.CaConfig;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterial;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Creates and loads local (KEK-encrypted) CA keys (FR-CA-8) — shared by
 * cold-start provisioning and CA rotation. Generation KEK-wraps a fresh ECDSA
 * key with a loud production warning; loading unwraps it transiently into a
 * signer.
 */
@Component
public class LocalCaFactory {

	private static final Logger LOG = LoggerFactory.getLogger(LocalCaFactory.class);

	private final KekProvider kekProvider;
	private final LocalCaKeyStore keyStore;
	private final OpenSshCertificateAssembler assembler;

	public LocalCaFactory(KekProvider kekProvider, LocalCaKeyStore keyStore, OpenSshCertificateAssembler assembler) {
		this.kekProvider = kekProvider;
		this.keyStore = keyStore;
		this.assembler = assembler;
	}

	/** A generated local CA: the config row and its KEK-wrapped key material. */
	public record Provisioned(CaConfig config, CaKeyMaterial material) {
	}

	/**
	 * Generate a new local ECDSA P-256 CA of the given kind/name/rotation state.
	 */
	public Provisioned create(String kind, String name, String rotationState) {
		warn(kind);
		CaKeyType keyType = CaKeyType.ECDSA_NISTP256;
		UUID configId = Uuids.v7();
		byte[] aad = aad(configId, keyType.keyTypeName(), kekProvider.reference());
		Kek kek = kekProvider.newKek();
		LocalCaKeyStore.GeneratedKey generated;
		try {
			generated = keyStore.generate(keyType, kek, aad);
		} finally {
			kek.destroy();
		}
		CaConfig config = new CaConfig(configId, name, kind, "local", "local:" + configId, keyType.algorithmId(),
				rotationState, "default", null, null, null);
		CaKeyMaterial material = CaKeyMaterial.create(configId, name, kekProvider.reference(),
				generated.wrapped().ciphertext(), generated.wrapped().iv(), generated.publicKeyX509(),
				keyType.keyTypeName());
		return new Provisioned(config, material);
	}

	/**
	 * The AAD binding a wrapped CA key to its row: {@code caConfigId | keyType |
	 * kekReference}. Identical on wrap (generate) and unwrap (load), so a wrapped
	 * blob cannot be lifted into a different CA's row (cross-CA substitution).
	 */
	private static byte[] aad(UUID caConfigId, String keyTypeName, String kekReference) {
		return (caConfigId + "|" + keyTypeName + "|" + kekReference).getBytes(java.nio.charset.StandardCharsets.UTF_8);
	}

	/**
	 * The CA public key as a {@code TrustedUserCAKeys} line, derived from the
	 * stored public material alone — no private-key unwrap (used to publish the
	 * trusted set).
	 */
	public String publicAuthorizedKey(CaConfig config, CaKeyMaterial material) {
		try {
			CaKeyType keyType = CaKeyType.fromAlgorithmId(config.algorithm());
			var publicKey = (java.security.interfaces.ECPublicKey) java.security.KeyFactory.getInstance("EC")
					.generatePublic(new java.security.spec.X509EncodedKeySpec(material.publicKey()));
			return io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys.toAuthorizedKey(publicKey, keyType,
					config.name());
		} catch (Exception e) {
			throw new IllegalStateException("failed to read CA public key for " + config.name(), e);
		}
	}

	/** Load a persisted local CA into a signer (unwraps the key transiently). */
	public SshCertSigner load(CaConfig config, CaKeyMaterial material) {
		warn(config.caKind());
		CaKeyType keyType = CaKeyType.fromAlgorithmId(config.algorithm());
		byte[] aad = aad(material.caConfigId(), material.keyType(), material.kekReference());
		Kek kek = kekProvider.newKek();
		try {
			LocalCaBackend backend = keyStore.load(keyType, kek, new Kek.Wrapped(material.iv(), material.wrappedKey()),
					material.publicKey(), aad);
			return new RawSignerCertSigner(backend, assembler);
		} finally {
			kek.destroy();
		}
	}

	// Warn on both generation and load (a restart only ever loads, so a
	// generation-only
	// warning would go silent after first boot).
	private void warn(String kind) {
		if (kekProvider.isDevDefault()) {
			LOG.warn("SECURITY: the local CA KEK is the built-in DEV default (public constant) — set a real KEK "
					+ "(sessionlayer.ca.local.kek-base64 / env). This is dev/test ONLY.");
		}
		LOG.warn("local CA backend in use for the {} CA; production SHOULD use KMS/KeyVault/Vault so the CA "
				+ "private key is never in-process (FR-CA-8, Design §14).", kind);
	}
}
