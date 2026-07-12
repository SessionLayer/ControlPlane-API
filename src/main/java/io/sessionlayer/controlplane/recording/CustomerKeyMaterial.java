package io.sessionlayer.controlplane.recording;

/**
 * The operator-configured customer PUBLIC key the Gateway seals the
 * per-recording data key to (FR-AUD-2, §15 crown jewels). PUBLIC material only
 * — the CP never holds the private half, so a platform operator cannot decrypt
 * a recording. {@code publicKey} is DER SubjectPublicKeyInfo (an EC P-256 point
 * for ECIES, an RSA public key for RSA-OAEP); {@code algorithm} is the seal
 * scheme ({@code ecies_p256} default | {@code rsa_oaep_sha256}); {@code keyRef}
 * is the operator's opaque reference (persisted as the recording's encryption
 * key ref).
 */
public record CustomerKeyMaterial(String keyRef, byte[] publicKey, String algorithm) {
}
