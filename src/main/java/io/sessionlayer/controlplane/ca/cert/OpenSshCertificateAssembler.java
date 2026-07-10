package io.sessionlayer.controlplane.ca.cert;

import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.wire.SshWriter;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/**
 * Assembles the OpenSSH certificate wire format (PROTOCOL.certkeys) — the
 * unforgiving part (FR-CA-6). For an ECDSA cert the fields, all
 * SSH-wire-encoded, in order are:
 *
 * <pre>
 *   string    cert-type name        ("ecdsa-sha2-nistp256-cert-v01@openssh.com")
 *   string    nonce                 (32 random bytes)
 *   string    curve name            } the certified key's type-specific fields
 *   string    Q (public point)      }
 *   uint64    serial
 *   uint32    type                  (1=user, 2=host)
 *   string    key id
 *   string    valid principals      (a string of packed name-strings)
 *   uint64    valid after
 *   uint64    valid before
 *   string    critical options      (sorted (name, string(value)) pairs — double length prefix)
 *   string    extensions            (sorted (name, empty) flag pairs)
 *   string    reserved              (empty)
 *   string    signature key         (the CA public-key blob)
 *   string    signature             (over everything above; appended after signing)
 * </pre>
 *
 * The signature covers all bytes from the leading cert-type name through the
 * signature-key field; {@link #buildToBeSigned} returns exactly those bytes and
 * {@link #assembleSigned} appends the signature string.
 *
 * <p>
 * The classic failure modes are handled here: value-carrying critical options
 * encode their value as an SSH {@code string} <b>inside</b> the option's
 * {@code data} string (the double length prefix), flag extensions have an
 * <b>empty</b> data string, and both sequences are byte-lexically sorted with
 * no duplicates ({@link CertificateParameters}).
 */
public final class OpenSshCertificateAssembler {

	private final SecureRandom random;

	public OpenSshCertificateAssembler() {
		this(new SecureRandom());
	}

	public OpenSshCertificateAssembler(SecureRandom random) {
		this.random = random;
	}

	/** A fresh 32-byte certificate nonce. */
	public byte[] newNonce() {
		byte[] nonce = new byte[32];
		random.nextBytes(nonce);
		return nonce;
	}

	/**
	 * The to-be-signed certificate bytes: everything from the cert-type name
	 * through the signature-key field (the signature itself is not included).
	 *
	 * @param keyType
	 *            the certificate/CA key type (fixes the cert-type name)
	 * @param nonce
	 *            32-byte nonce (use {@link #newNonce()})
	 * @param certifiedKeyBody
	 *            the certified key's type-specific fields (for ECDSA,
	 *            {@code string(curve) || string(Q)})
	 * @param params
	 *            serial/type/keyId/principals/validity/options/extensions
	 * @param caPublicKeyBlob
	 *            the CA public-key blob (the signature-key field)
	 */
	public byte[] buildToBeSigned(CaKeyType keyType, byte[] nonce, byte[] certifiedKeyBody,
			CertificateParameters params, byte[] caPublicKeyBlob) {
		SshWriter w = new SshWriter();
		w.writeString(keyType.certTypeName());
		w.writeString(nonce);
		w.writeBytes(certifiedKeyBody); // string(curve) || string(Q)
		w.writeUint64(params.serial());
		w.writeUint32(params.type().value());
		w.writeString(params.keyId());
		w.writeString(encodePrincipals(params));
		w.writeUint64(epochSeconds(params.validAfter()));
		w.writeUint64(epochSeconds(params.validBefore()));
		w.writeString(encodeCriticalOptions(params));
		w.writeString(encodeExtensions(params));
		w.writeString(new byte[0]); // reserved
		w.writeString(caPublicKeyBlob); // signature key
		return w.toByteArray();
	}

	/**
	 * Append the signature string to the TBS bytes to form the full certificate
	 * blob.
	 */
	public byte[] assembleSigned(byte[] toBeSigned, byte[] signatureField) {
		return new SshWriter().writeBytes(toBeSigned).writeString(signatureField).toByteArray();
	}

	/**
	 * The {@code "<cert-type> <base64(blob)> <comment>"} single line ssh-keygen
	 * parses.
	 */
	public String toCertificateLine(CaKeyType keyType, byte[] certificateBlob, String comment) {
		String b64 = Base64.getEncoder().encodeToString(certificateBlob);
		return keyType.certTypeName() + " " + b64 + (comment == null || comment.isBlank() ? "" : " " + comment);
	}

	// valid principals: a string containing zero or more packed strings.
	private static byte[] encodePrincipals(CertificateParameters params) {
		SshWriter w = new SshWriter();
		for (String p : params.principals()) {
			w.writeString(p);
		}
		return w.toByteArray();
	}

	// critical options: sorted (name, data) where data = string(value) — the value
	// is
	// itself an SSH string, giving the double length prefix.
	private static byte[] encodeCriticalOptions(CertificateParameters params) {
		SshWriter w = new SshWriter();
		for (Map.Entry<String, String> e : params.criticalOptions().entrySet()) {
			w.writeString(e.getKey());
			w.writeString(new SshWriter().writeString(e.getValue()).toByteArray());
		}
		return w.toByteArray();
	}

	// extensions: sorted (name, empty) — a flag's data is a zero-length string
	// (still
	// its 4-byte length prefix). Distinguishing this from a value option is THE
	// bug.
	private static byte[] encodeExtensions(CertificateParameters params) {
		SshWriter w = new SshWriter();
		for (String name : params.extensions()) {
			w.writeString(name);
			w.writeString(new byte[0]);
		}
		return w.toByteArray();
	}

	private static long epochSeconds(java.time.Instant instant) {
		return instant.getEpochSecond();
	}
}
