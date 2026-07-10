package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.ca.backend.SignerBackend;
import io.sessionlayer.controlplane.ca.backend.aws.KmsCaBackend;
import io.sessionlayer.controlplane.ca.backend.aws.KmsSigner;
import io.sessionlayer.controlplane.ca.backend.azure.AzureKeyVaultCaBackend;
import io.sessionlayer.controlplane.ca.backend.azure.KeyVaultSigner;
import io.sessionlayer.controlplane.ca.backend.vault.VaultCaCertSigner;
import io.sessionlayer.controlplane.ca.backend.vault.VaultSshEngine;
import io.sessionlayer.controlplane.ca.cert.CertificateProfiles;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/**
 * Cloud CA backends (D7): the KMS/Azure/Vault backends are implemented in full
 * and their signature normalization (FR-SIGN-2) and TBS assembly are exercised
 * deterministically with an <b>injected signer double</b> (correct testing of
 * an external dependency, not a deferral — no cloud credentials in CI). The
 * doubles are backed by a real EC key so the resulting certificate verifies
 * cryptographically.
 */
class CloudBackendNormalizationTest {

	private final KeyPair caKeyPair = ecKeyPair();

	private static KeyPair ecKeyPair() {
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
			g.initialize(new ECGenParameterSpec("secp256r1"));
			return g.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	private static ECPublicKey subjectKey() {
		return (ECPublicKey) ecKeyPair().getPublic();
	}

	/**
	 * Sign a raw SHA-256 digest with the CA key (emulates a HSM DIGEST-mode sign).
	 */
	private byte[] signDigestDer(byte[] digest) throws Exception {
		Signature s = Signature.getInstance("NONEwithECDSA");
		s.initSign((PrivateKey) caKeyPair.getPrivate());
		s.update(digest);
		return s.sign();
	}

	@Test
	void kmsBackendNormalizesDerAndProducesAVerifiableCert() throws Exception {
		KmsSigner kms = new KmsSigner() {
			public ECPublicKey publicKey() {
				return (ECPublicKey) caKeyPair.getPublic();
			}

			public byte[] signDigestDer(byte[] digest) {
				try {
					return CloudBackendNormalizationTest.this.signDigestDer(digest);
				} catch (Exception e) {
					throw new IllegalStateException(e);
				}
			}
		};
		SignerBackend backend = new KmsCaBackend(CaKeyType.ECDSA_NISTP256, kms);
		assertVerifiableCert(new RawSignerCertSigner(backend));
	}

	@Test
	void azureBackendNormalizesP1363AndProducesAVerifiableCert() throws Exception {
		KeyVaultSigner keyVault = new KeyVaultSigner() {
			public ECPublicKey publicKey() {
				return (ECPublicKey) caKeyPair.getPublic();
			}

			public byte[] signDigestP1363(byte[] digest) {
				try {
					// Azure returns P1363 (r||s); derive it from the DER the key produces.
					EcdsaSignatures.RS rs = EcdsaSignatures
							.fromDer(CloudBackendNormalizationTest.this.signDigestDer(digest));
					byte[] out = new byte[64];
					byte[] r = fixed(rs.r());
					byte[] s = fixed(rs.s());
					System.arraycopy(r, 0, out, 0, 32);
					System.arraycopy(s, 0, out, 32, 32);
					return out;
				} catch (Exception e) {
					throw new IllegalStateException(e);
				}
			}
		};
		SignerBackend backend = new AzureKeyVaultCaBackend(CaKeyType.ECDSA_NISTP256, keyVault);
		assertVerifiableCert(new RawSignerCertSigner(backend));
	}

	@Test
	void vaultSignerUsesSshSignAndReturnsACertOnly() {
		AtomicReference<String> endpoint = new AtomicReference<>();
		VaultSshEngine engine = new VaultSshEngine() {
			public String caPublicKeyLine() {
				return "ecdsa-sha2-nistp256 "
						+ java.util.Base64.getEncoder()
								.encodeToString(io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys
										.encode((ECPublicKey) caKeyPair.getPublic(), CaKeyType.ECDSA_NISTP256))
						+ " vault-ca";
			}

			public SignedCertificate sign(String role, String publicKeyOpenSshLine, SignRequest request) {
				endpoint.set("POST /v1/ssh/sign/" + role); // never /ssh/issue
				// A canned Vault response cert (structure not important for this assertion).
				return new SignedCertificate("ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAcanned vault-signed");
			}
		};
		VaultCaCertSigner signer = new VaultCaCertSigner(CaKeyType.ECDSA_NISTP256, engine, "sessionlayer-role");
		var params = CertificateProfiles.innerLegSessionCert("sess-v", "u", "deploy", "10.0.0.0/8", Set.of("shell"), 1L,
				Instant.now());
		var cert = signer.signCertificate(new CertificateRequest(subjectKey(), params));

		assertThat(cert.certificateLine()).contains("vault-signed");
		assertThat(endpoint.get()).contains("/ssh/sign/").doesNotContain("/ssh/issue");
		// Vault path exposes no raw-sign primitive.
		assertThatThrownBy(() -> signer.rawSign(new byte[]{1})).isInstanceOf(UnsupportedOperationException.class);
	}

	private void assertVerifiableCert(SshCertSigner signer) throws Exception {
		var params = CertificateProfiles.innerLegSessionCert("sess-cloud", "alice", "deploy", "10.0.0.0/8",
				Set.of("shell", "exec"), 7L, Instant.now());
		OpenSshCertificate cert = signer.signCertificate(new CertificateRequest(subjectKey(), params));
		assertThat(CertTestSupport.verifyEcdsaCert(cert.blob(), (ECPublicKey) caKeyPair.getPublic())).isTrue();
		assertThat(signer.capabilities().supports("ecdsa-p256")).isTrue();
	}

	private static byte[] fixed(BigInteger v) {
		byte[] raw = v.toByteArray();
		byte[] out = new byte[32];
		int start = (raw.length > 32) ? raw.length - 32 : 0;
		int len = raw.length - start;
		System.arraycopy(raw, start, out, 32 - len, len);
		return out;
	}

	@Test
	void backendListsUnsupportedAlgorithmAsAbsent() {
		SignerBackend backend = new KmsCaBackend(CaKeyType.ECDSA_NISTP256, new KmsSigner() {
			public ECPublicKey publicKey() {
				return (ECPublicKey) caKeyPair.getPublic();
			}

			public byte[] signDigestDer(byte[] d) {
				return new byte[0];
			}
		});
		assertThat(backend.capabilities().supports("ecdsa-p256")).isTrue();
		assertThat(backend.capabilities().supports("ed25519")).isFalse();
		assertThat(backend.capabilities().supports("rsa-4096")).isFalse();
	}
}
