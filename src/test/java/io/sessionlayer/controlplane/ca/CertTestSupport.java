package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.wire.SshReader;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.math.BigInteger;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * Shared test helpers: parse an OpenSSH cert blob and verify its CA signature.
 */
final class CertTestSupport {

	private CertTestSupport() {
	}

	/** True if the CA signature over the certificate's TBS bytes verifies. */
	static boolean verifyEcdsaCert(byte[] blob, ECPublicKey caPublicKey) throws Exception {
		SshReader r = new SshReader(blob);
		for (int i = 0; i < 4; i++) {
			r.readString(); // cert-type, nonce, curve, Q
		}
		r.readUint64();
		r.readUint32();
		r.readString();
		r.readString(); // serial, type, keyId, principals
		r.readUint64();
		r.readUint64(); // validity
		r.readString();
		r.readString();
		r.readString();
		r.readString(); // critical, extensions, reserved, signature key
		int tbsLen = r.position();
		byte[] signatureField = r.readString();
		byte[] tbs = Arrays.copyOfRange(blob, 0, tbsLen);

		SshReader sig = new SshReader(signatureField);
		sig.readStringUtf8();
		SshReader inner = new SshReader(sig.readString());
		BigInteger rr = inner.readMpint();
		BigInteger ss = inner.readMpint();
		Signature verifier = Signature.getInstance("SHA256withECDSA");
		verifier.initVerify(caPublicKey);
		verifier.update(tbs);
		return verifier.verify(rsToDer(rr, ss));
	}

	static byte[] rsToDer(BigInteger r, BigInteger s) {
		byte[] rInt = derInteger(r.toByteArray());
		byte[] sInt = derInteger(s.toByteArray());
		SshWriter w = new SshWriter().writeByte(0x30);
		writeLen(w, rInt.length + sInt.length);
		return w.writeBytes(rInt).writeBytes(sInt).toByteArray();
	}

	private static byte[] derInteger(byte[] magnitude) {
		SshWriter w = new SshWriter().writeByte(0x02);
		writeLen(w, magnitude.length);
		return w.writeBytes(magnitude).toByteArray();
	}

	private static void writeLen(SshWriter w, int len) {
		if (len < 0x80) {
			w.writeByte(len);
		} else {
			w.writeByte(0x81).writeByte(len);
		}
	}
}
