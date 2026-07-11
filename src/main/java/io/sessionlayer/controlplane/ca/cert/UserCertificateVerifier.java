package io.sessionlayer.controlplane.ca.cert;

import io.sessionlayer.controlplane.authz.Cidrs;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import io.sessionlayer.controlplane.ca.wire.SshReader;
import java.math.BigInteger;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Validates a presented OpenSSH <b>user</b> certificate against the user-facing
 * CA (Design §3.1, the outer-leg Vault-user-cert path; FR-CA-2). A pure
 * function over the certificate bytes and the currently-trusted user-CA keys —
 * no I/O, no reactive context. The outcome is a single generic
 * {@link Verdict#fail} for ANY reason (untrusted CA / expired / wrong type /
 * malformed / wrong source), so the outer-leg auth surface leaks no existence
 * (§7.1, FR-AUTH-16); the reason is for the server-side decision log only.
 *
 * <p>
 * Trust follows OpenSSH semantics: the certificate's embedded signature-key
 * field must byte-equal one of the trusted user-CA keys
 * ({@code TrustedUserCAKeys} from
 * {@link io.sessionlayer.controlplane.ca.CaRotationService#trustedCaKeys}), and
 * the CA signature must verify over the certificate's to-be-signed bytes. The
 * certified user key itself is not re-verified here — the SSH transport proved
 * possession of its private key on the Gateway; this answers only "is this a
 * valid, trusted, in-window user cert, and who is it?". SessionLayer's user CA
 * is ECDSA (P-256/384/521), so only an ECDSA CA signature is verifiable; any
 * other CA-key type fails closed.
 */
public final class UserCertificateVerifier {

	/**
	 * Critical options this resolver understands. OpenSSH mandates rejecting a
	 * certificate carrying an unrecognised critical option, so any other name fails
	 * closed. {@code source-address} is enforced here (deny-only); {@code
	 * force-command} is accepted and left for the node/session layer to enforce.
	 */
	private static final String OPT_SOURCE_ADDRESS = "source-address";
	private static final String OPT_FORCE_COMMAND = "force-command";

	private UserCertificateVerifier() {
	}

	/**
	 * The verification outcome: resolved identity + cert-scoped principals, or a
	 * reason.
	 */
	public record Verdict(boolean resolved, String identity, List<String> principals, String reason) {

		static Verdict fail(String reason) {
			return new Verdict(false, null, List.of(), reason);
		}

		static Verdict ok(String identity, List<String> principals) {
			return new Verdict(true, identity, List.copyOf(principals), "ok");
		}
	}

	/**
	 * Verify {@code certificateBlob} against {@code trustedUserCaKeys} (authorized-
	 * key lines) at {@code now} with a small {@code skew}, enforcing any pinned
	 * {@code source-address} against {@code sourceIp} (deny-only).
	 */
	public static Verdict verify(byte[] certificateBlob, List<String> trustedUserCaKeys, String sourceIp, Instant now,
			Duration skew) {
		try {
			return verifyChecked(certificateBlob, trustedUserCaKeys, sourceIp, now, skew);
		} catch (RuntimeException malformed) {
			return Verdict.fail("malformed");
		}
	}

	private static Verdict verifyChecked(byte[] blob, List<String> trustedUserCaKeys, String sourceIp, Instant now,
			Duration skew) {
		SshReader reader = new SshReader(blob);
		String certType = reader.readStringUtf8();
		int certifiedKeyFields = certifiedKeyFieldCount(certType);
		if (certifiedKeyFields < 0) {
			return Verdict.fail("unknown_cert_type");
		}
		reader.readString(); // nonce
		for (int i = 0; i < certifiedKeyFields; i++) {
			reader.readString(); // certified key's type-specific fields (skipped)
		}
		reader.readUint64(); // serial
		long type = reader.readUint32();
		String keyId = reader.readStringUtf8();
		List<String> principals = readPrincipals(reader.readString());
		long validAfter = reader.readUint64();
		long validBefore = reader.readUint64();
		byte[] criticalOptions = reader.readString();
		reader.readString(); // extensions (non-critical: unknown ones are ignored)
		reader.readString(); // reserved
		byte[] caKeyBlob = reader.readString(); // signature key
		int tbsLength = reader.position();
		byte[] signatureField = reader.readString();
		if (reader.hasRemaining()) {
			return Verdict.fail("trailing_bytes");
		}

		TrustedCa ca = matchTrustedCa(caKeyBlob, trustedUserCaKeys);
		if (ca == null) {
			return Verdict.fail("untrusted_ca");
		}
		if (!verifySignature(Arrays.copyOfRange(blob, 0, tbsLength), signatureField, ca)) {
			return Verdict.fail("bad_signature");
		}
		if (type != CertType.USER.value()) {
			return Verdict.fail("not_user_cert");
		}
		if (!withinWindow(now, validAfter, validBefore, skew)) {
			return Verdict.fail("outside_validity_window");
		}
		String sourceOutcome = enforceCriticalOptions(criticalOptions, sourceIp);
		if (sourceOutcome != null) {
			return Verdict.fail(sourceOutcome);
		}
		if (keyId.isBlank() || principals.stream().allMatch(p -> p == null || p.isBlank())) {
			// An empty key-id has no subject; empty principals is an any-login wildcard.
			return Verdict.fail("no_identity_or_principals");
		}
		return Verdict.ok(keyId, principals);
	}

	/**
	 * The count of SSH {@code string} fields the certified key contributes between
	 * the nonce and the serial (each is length-prefixed, so all can be skipped
	 * uniformly). Returns -1 for a cert type we cannot parse.
	 */
	private static int certifiedKeyFieldCount(String certType) {
		return switch (certType) {
			case "ssh-ed25519-cert-v01@openssh.com" -> 1;
			case "ssh-rsa-cert-v01@openssh.com" -> 2; // e, n
			case "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
					"ecdsa-sha2-nistp521-cert-v01@openssh.com" ->
				2; // curve, Q
			case "sk-ssh-ed25519-cert-v01@openssh.com" -> 2; // pk, application
			case "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com" -> 3; // curve, Q, application
			default -> -1;
		};
	}

	private static List<String> readPrincipals(byte[] field) {
		SshReader reader = new SshReader(field);
		List<String> out = new ArrayList<>();
		while (reader.hasRemaining()) {
			out.add(reader.readStringUtf8());
		}
		return out;
	}

	private record TrustedCa(CaKeyType keyType, ECPublicKey publicKey) {
	}

	private static TrustedCa matchTrustedCa(byte[] caKeyBlob, List<String> trustedUserCaKeys) {
		if (trustedUserCaKeys == null) {
			return null;
		}
		for (String line : trustedUserCaKeys) {
			String[] parts = line.trim().split("\\s+");
			if (parts.length < 2) {
				continue;
			}
			byte[] trustedBlob;
			try {
				trustedBlob = Base64.getDecoder().decode(parts[1]);
			} catch (IllegalArgumentException notBase64) {
				continue;
			}
			if (!Arrays.equals(trustedBlob, caKeyBlob)) {
				continue;
			}
			try {
				// Only ECDSA user CAs are verifiable; a non-ECDSA key-type name throws → skip.
				CaKeyType keyType = CaKeyType.fromKeyTypeName(parts[0]);
				return new TrustedCa(keyType, SshEcdsaPublicKeys.parse(trustedBlob));
			} catch (RuntimeException unsupported) {
				return null;
			}
		}
		return null;
	}

	private static boolean verifySignature(byte[] toBeSigned, byte[] signatureField, TrustedCa ca) {
		try {
			SshReader sig = new SshReader(signatureField);
			String signatureAlg = sig.readStringUtf8();
			if (!ca.keyType().keyTypeName().equals(signatureAlg)) {
				return false; // signature algorithm must match the trusted CA key
			}
			SshReader inner = new SshReader(sig.readString());
			BigInteger r = inner.readMpint();
			BigInteger s = inner.readMpint();
			Signature verifier = Signature.getInstance(ca.keyType().signatureAlgorithm());
			verifier.initVerify(ca.publicKey());
			verifier.update(toBeSigned);
			return verifier.verify(EcdsaSignatures.toDer(new EcdsaSignatures.RS(r, s)));
		} catch (RuntimeException | java.security.GeneralSecurityException invalid) {
			return false;
		}
	}

	private static boolean withinWindow(Instant now, long validAfter, long validBefore, Duration skew) {
		long nowSeconds = now.getEpochSecond();
		long skewSeconds = skew.getSeconds();
		return Long.compareUnsigned(nowSeconds + skewSeconds, validAfter) >= 0
				&& Long.compareUnsigned(nowSeconds - skewSeconds, validBefore) <= 0;
	}

	/**
	 * Reject unknown critical options and enforce a pinned {@code source-address}
	 * (deny-only): returns a fail reason, or {@code null} when the options are
	 * acceptable for {@code sourceIp}.
	 */
	private static String enforceCriticalOptions(byte[] criticalOptions, String sourceIp) {
		SshReader reader = new SshReader(criticalOptions);
		while (reader.hasRemaining()) {
			String name = reader.readStringUtf8();
			byte[] data = reader.readString();
			switch (name) {
				case OPT_SOURCE_ADDRESS -> {
					String cidrList = new SshReader(data).readStringUtf8();
					if (!sourceAllowed(cidrList, sourceIp)) {
						return "source_address_denied";
					}
				}
				case OPT_FORCE_COMMAND -> {
					// Accepted; command restriction is the node/session layer's concern.
				}
				default -> {
					return "unknown_critical_option";
				}
			}
		}
		return null;
	}

	private static boolean sourceAllowed(String cidrList, String sourceIp) {
		if (sourceIp == null || sourceIp.isBlank()) {
			return false; // pinned source but no known client IP → fail closed
		}
		for (String cidr : cidrList.split(",")) {
			String trimmed = cidr.trim();
			if (trimmed.isEmpty()) {
				continue;
			}
			try {
				if (Cidrs.contains(trimmed.indexOf('/') < 0 ? trimmed + hostBits(trimmed) : trimmed, sourceIp)) {
					return true;
				}
			} catch (RuntimeException malformed) {
				// A malformed CIDR entry never grants; try the next (deny-only).
			}
		}
		return false;
	}

	private static String hostBits(String address) {
		return address.indexOf(':') >= 0 ? "/128" : "/32";
	}
}
