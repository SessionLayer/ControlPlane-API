package io.sessionlayer.controlplane.breakglass;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * The sk-ecdsa FIDO2 wire parser + OpenSSH SHA-256 fingerprint (FR-ACC-6). The
 * fingerprint MUST be byte-identical to {@code ssh-keygen -lf} (which the
 * Gateway sends), i.e. {@code "SHA256:" + base64-nopad(SHA-256(blob))} over the
 * exact wire bytes; and a non-sk / malformed key must fail closed.
 */
class SkEcdsaPublicKeyTest {

	@Test
	void parsesFingerprintAndApplication() {
		byte[] blob = skBlob("ssh:", (byte) 0x11);

		SkEcdsaPublicKey.Parsed parsed = SkEcdsaPublicKey.parse(blob);

		assertThat(parsed.application()).isEqualTo("ssh:");
		assertThat(parsed.fingerprint()).isEqualTo(expectedFingerprint(blob));
		assertThat(parsed.fingerprint()).startsWith("SHA256:").doesNotContain("=");
	}

	@Test
	void distinctKeysHaveDistinctFingerprints() {
		assertThat(SkEcdsaPublicKey.parse(skBlob("ssh:", (byte) 0x11)).fingerprint())
				.isNotEqualTo(SkEcdsaPublicKey.parse(skBlob("ssh:", (byte) 0x22)).fingerprint());
	}

	@Test
	void rejectsWrongKeyType() {
		byte[] plainEcdsa = new SshWriter().writeString("ecdsa-sha2-nistp256").writeString("nistp256")
				.writeString(point((byte) 0x11)).toByteArray();
		assertThatThrownBy(() -> SkEcdsaPublicKey.parse(plainEcdsa)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void rejectsTrailingGarbageAndEmpty() {
		byte[] withTrailer = new SshWriter().writeString(SkEcdsaPublicKey.KEY_TYPE).writeString("nistp256")
				.writeString(point((byte) 0x11)).writeString("ssh:").writeBytes(new byte[]{7, 7}).toByteArray();
		assertThatThrownBy(() -> SkEcdsaPublicKey.parse(withTrailer)).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> SkEcdsaPublicKey.parse(new byte[0])).isInstanceOf(IllegalArgumentException.class);
	}

	private static byte[] skBlob(String application, byte fill) {
		return new SshWriter().writeString(SkEcdsaPublicKey.KEY_TYPE).writeString("nistp256").writeString(point(fill))
				.writeString(application).toByteArray();
	}

	// A structurally valid uncompressed P-256 point (0x04 || 32-byte X || 32-byte
	// Y);
	// the fingerprint is a pure hash of the wire bytes, so on-curve validity is not
	// required to exercise parse + fingerprint.
	private static byte[] point(byte fill) {
		byte[] q = new byte[65];
		q[0] = 0x04;
		for (int i = 1; i < q.length; i++) {
			q[i] = fill;
		}
		return q;
	}

	private static String expectedFingerprint(byte[] blob) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(blob);
			return "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest);
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}
}
