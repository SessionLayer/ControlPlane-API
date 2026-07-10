package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import io.sessionlayer.controlplane.ca.wire.SshReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.Test;

/**
 * FR-SIGN-2 signature normalization: AWS KMS DER and Azure P1363 {@code r‖s}
 * must both normalize to the same OpenSSH {@code mpint r,s}. Known-vector +
 * cross-format-equivalence tests with an injected signer double (a JCA
 * {@code Signature}), plus strict-DER rejection.
 */
class EcdsaSignaturesTest {

	@Test
	void fromDerKnownVectors() {
		// SEQUENCE { INTEGER 1, INTEGER 2 }
		var rs = EcdsaSignatures.fromDer(new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02});
		assertThat(rs.r()).isEqualTo(BigInteger.ONE);
		assertThat(rs.s()).isEqualTo(BigInteger.TWO);

		// High-bit values carry a DER leading 0x00: INTEGER 0x0080 = 128.
		var hi = EcdsaSignatures
				.fromDer(new byte[]{0x30, 0x08, 0x02, 0x02, 0x00, (byte) 0x80, 0x02, 0x02, 0x00, (byte) 0x80});
		assertThat(hi.r()).isEqualTo(BigInteger.valueOf(128));
		assertThat(hi.s()).isEqualTo(BigInteger.valueOf(128));
	}

	@Test
	void fromP1363KnownVector() {
		byte[] raw = new byte[64]; // p256: 32-byte r || 32-byte s
		raw[31] = 0x01; // r = 1
		raw[63] = 0x02; // s = 2
		var rs = EcdsaSignatures.fromP1363(raw, CaKeyType.ECDSA_NISTP256);
		assertThat(rs.r()).isEqualTo(BigInteger.ONE);
		assertThat(rs.s()).isEqualTo(BigInteger.TWO);
	}

	@Test
	void derAndP1363OfSameSignatureNormalizeIdentically() throws Exception {
		// The injected "signer double": a real JCA ECDSA signature (DER). We then
		// re-express the SAME (r,s) as Azure-style P1363 and assert both paths agree.
		KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
		g.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair kp = g.generateKeyPair();
		Signature signer = Signature.getInstance("SHA256withECDSA");
		signer.initSign(kp.getPrivate());
		signer.update("to-be-signed".getBytes());
		byte[] der = signer.sign();

		var fromDer = EcdsaSignatures.fromDer(der);
		byte[] p1363 = new byte[64];
		System.arraycopy(fixed(fromDer.r()), 0, p1363, 0, 32);
		System.arraycopy(fixed(fromDer.s()), 0, p1363, 32, 32);
		var fromP1363 = EcdsaSignatures.fromP1363(p1363, CaKeyType.ECDSA_NISTP256);

		assertThat(fromP1363.r()).isEqualTo(fromDer.r());
		assertThat(fromP1363.s()).isEqualTo(fromDer.s());
	}

	@Test
	void signatureBlobStructureIsAlgThenMpints() {
		var rs = new EcdsaSignatures.RS(BigInteger.valueOf(0x80), BigInteger.valueOf(0x7F));
		byte[] blob = EcdsaSignatures.encodeSignatureBlob(CaKeyType.ECDSA_NISTP256, rs);
		SshReader r = new SshReader(blob);
		assertThat(r.readStringUtf8()).isEqualTo("ecdsa-sha2-nistp256");
		SshReader inner = new SshReader(r.readString());
		// 0x80 has the high bit set -> mpint gets a leading 0x00 (2 bytes); 0x7F does
		// not.
		assertThat(inner.readMpint()).isEqualTo(BigInteger.valueOf(0x80));
		assertThat(inner.readMpint()).isEqualTo(BigInteger.valueOf(0x7F));
	}

	@Test
	void strictDerRejectsGarbageAndBadTags() {
		assertThatThrownBy(
				() -> EcdsaSignatures.fromDer(new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00}))
				.isInstanceOf(IllegalArgumentException.class); // trailing byte
		assertThatThrownBy(() -> EcdsaSignatures.fromDer(new byte[]{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02}))
				.isInstanceOf(IllegalArgumentException.class); // not a SEQUENCE
	}

	private static byte[] fixed(BigInteger v) {
		byte[] raw = v.toByteArray();
		byte[] out = new byte[32];
		int start = (raw.length > 32) ? raw.length - 32 : 0;
		int len = raw.length - start;
		System.arraycopy(raw, start, out, 32 - len, len);
		return out;
	}
}
