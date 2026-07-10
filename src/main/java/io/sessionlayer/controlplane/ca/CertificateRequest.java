package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.cert.CertificateParameters;
import java.security.interfaces.ECPublicKey;

/**
 * A request to sign a certificate: the <b>public key to certify</b> (the
 * Gateway generates the inner keypair and presents only the public key —
 * D2/§3.3; the CP never receives a private key) plus the certificate
 * parameters.
 *
 * @param subjectPublicKey
 *            the ECDSA public key being certified (never a private key)
 * @param parameters
 *            serial/type/keyId/principals/validity/options/extensions
 */
public record CertificateRequest(ECPublicKey subjectPublicKey, CertificateParameters parameters) {
}
