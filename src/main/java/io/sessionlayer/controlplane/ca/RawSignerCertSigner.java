package io.sessionlayer.controlplane.ca;

import io.sessionlayer.controlplane.ca.backend.SignerBackend;
import io.sessionlayer.controlplane.ca.cert.OpenSshCertificateAssembler;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import io.sessionlayer.controlplane.ca.sign.EcdsaSignatures;
import java.security.interfaces.ECPublicKey;

/**
 * The shared {@link SshCertSigner} for raw-signer backends (local / AWS KMS /
 * Azure Key Vault). It assembles the to-be-signed certificate with the shared
 * {@link OpenSshCertificateAssembler}, delegates the actual signing to the
 * injected {@link SignerBackend} (which normalizes its native signature to
 * {@code (r, s)}), and appends the OpenSSH signature field.
 */
public final class RawSignerCertSigner implements SshCertSigner {

	private final SignerBackend backend;
	private final OpenSshCertificateAssembler assembler;

	public RawSignerCertSigner(SignerBackend backend, OpenSshCertificateAssembler assembler) {
		this.backend = backend;
		this.assembler = assembler;
	}

	public RawSignerCertSigner(SignerBackend backend) {
		this(backend, new OpenSshCertificateAssembler());
	}

	@Override
	public CaKeyType keyType() {
		return backend.keyType();
	}

	@Override
	public byte[] caPublicKeyBlob() {
		return SshEcdsaPublicKeys.encode(backend.publicKey(), backend.keyType());
	}

	@Override
	public String caAuthorizedKey(String comment) {
		return SshEcdsaPublicKeys.toAuthorizedKey(backend.publicKey(), backend.keyType(), comment);
	}

	@Override
	public SignerCapabilities capabilities() {
		return backend.capabilities();
	}

	@Override
	public OpenSshCertificate signCertificate(CertificateRequest request) {
		CaKeyType keyType = backend.keyType();
		requireSameCurve(request.subjectPublicKey(), keyType);
		byte[] nonce = assembler.newNonce();
		byte[] subjectBody = SshEcdsaPublicKeys.encodeCurveAndPoint(request.subjectPublicKey(), keyType);
		byte[] caBlob = caPublicKeyBlob();
		byte[] toBeSigned = assembler.buildToBeSigned(keyType, nonce, subjectBody, request.parameters(), caBlob);
		EcdsaSignatures.RS rs = backend.sign(toBeSigned);
		byte[] signatureField = EcdsaSignatures.encodeSignatureBlob(keyType, rs);
		byte[] blob = assembler.assembleSigned(toBeSigned, signatureField);
		String line = assembler.toCertificateLine(keyType, blob, request.parameters().keyId());
		return new OpenSshCertificate(keyType, blob, line, request.parameters().serial(), request.parameters().keyId());
	}

	@Override
	public EcdsaSignatures.RS rawSign(byte[] toBeSigned) {
		return backend.sign(toBeSigned);
	}

	// This session certifies subject keys of the same curve as the CA (the
	// inner-leg
	// keypair the Gateway generates matches the session CA, D6). Reject a mismatch
	// rather than silently emit a wrong-width point (mixed subject/CA types:
	// future).
	private static void requireSameCurve(ECPublicKey subject, CaKeyType keyType) {
		int subjectBytes = (subject.getParams().getCurve().getField().getFieldSize() + 7) / 8;
		if (subjectBytes != keyType.coordinateBytes()) {
			throw new IllegalArgumentException("subject key curve width " + subjectBytes + " != CA "
					+ keyType.algorithmId() + " (" + keyType.coordinateBytes() + ")");
		}
	}
}
