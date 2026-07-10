package io.sessionlayer.controlplane.ca;

import java.util.Base64;

/**
 * A signed OpenSSH certificate: the raw wire blob plus the single-line
 * {@code "<cert-type> <base64> <comment>"} form that {@code ssh-keygen -L} and
 * {@code TrustedUserCAKeys}-trusting {@code sshd} consume.
 *
 * @param keyType
 *            the certificate key type
 * @param blob
 *            the full signed certificate wire bytes
 * @param certificateLine
 *            the {@code authorized_keys}-style single line
 * @param serial
 *            the certificate serial
 * @param keyId
 *            the certificate key id
 */
public record OpenSshCertificate(CaKeyType keyType, byte[] blob, String certificateLine, long serial, String keyId) {

	/**
	 * Base64 of the certificate blob (the middle token of
	 * {@link #certificateLine()}).
	 */
	public String base64() {
		return Base64.getEncoder().encodeToString(blob);
	}
}
