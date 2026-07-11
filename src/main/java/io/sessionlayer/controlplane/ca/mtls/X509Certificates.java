package io.sessionlayer.controlplane.ca.mtls;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * X.509 helpers for the internal mTLS CA (Session Four), built on BouncyCastle.
 * We do NOT hand-roll DER: BC assembles the TBS structure, extensions and
 * signature. Both the local backend and the (unit-tested) cloud seam issue the
 * same certificate shape through {@link #issueLeaf}. The CA and its leaves are
 * ECDSA P-256 signed with {@code SHA256withECDSA} using the JDK's default
 * signature/certificate providers (no global BouncyCastle provider registration
 * — the footprint stays minimal).
 */
public final class X509Certificates {

	/** ECDSA P-256 signature algorithm for the internal mTLS CA (D6). */
	public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

	private X509Certificates() {
	}

	/**
	 * Self-sign an internal CA certificate over {@code caKeyPair}. BasicConstraints
	 * CA=true with pathLen 0 (it signs only leaves), KeyUsage
	 * {@code keyCertSign|cRLSign}, and a Subject Key Identifier.
	 */
	public static X509Certificate selfSignCa(String commonName, PublicKey caPublicKey, PrivateKey caPrivateKey,
			BigInteger serial, Instant notBefore, Instant notAfter) {
		try {
			X500Name subject = new X500Name("CN=" + commonName);
			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serial, Date.from(notBefore),
					Date.from(notAfter), subject, caPublicKey);
			JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
			builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(caPublicKey));
			ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(caPrivateKey);
			return convert(builder.build(signer));
		} catch (Exception e) {
			throw new IllegalStateException("failed to self-sign internal mTLS CA certificate", e);
		}
	}

	/**
	 * Issue a leaf certificate for {@code spec}, signed by the CA cert/key.
	 * BasicConstraints CA=false, KeyUsage {@code digitalSignature}, a single EKU
	 * per {@link LeafPurpose}, the requested SANs, and SKI/AKI.
	 */
	public static X509Certificate issueLeaf(X509Certificate caCertificate, PrivateKey caPrivateKey,
			LeafCertificateSpec spec) {
		try {
			X500Name issuer = new X500Name(caCertificate.getSubjectX500Principal().getName());
			X500Name subject = new X500Name("CN=" + spec.subjectCommonName());
			JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, spec.serial(),
					Date.from(spec.notBefore()), Date.from(spec.notAfter()), subject, spec.subjectPublicKey());
			JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
			builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
			KeyPurposeId purposeId = spec.purpose() == LeafPurpose.SERVER
					? KeyPurposeId.id_kp_serverAuth
					: KeyPurposeId.id_kp_clientAuth;
			builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposeId));
			GeneralNames sans = subjectAlternativeNames(spec);
			if (sans != null) {
				builder.addExtension(Extension.subjectAlternativeName, false, sans);
			}
			builder.addExtension(Extension.subjectKeyIdentifier, false,
					ext.createSubjectKeyIdentifier(spec.subjectPublicKey()));
			builder.addExtension(Extension.authorityKeyIdentifier, false,
					ext.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));
			ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(caPrivateKey);
			return convert(builder.build(signer));
		} catch (Exception e) {
			throw new IllegalStateException("failed to issue internal mTLS leaf certificate", e);
		}
	}

	private static GeneralNames subjectAlternativeNames(LeafCertificateSpec spec) {
		List<GeneralName> names = new ArrayList<>();
		for (String dns : spec.dnsSans()) {
			names.add(new GeneralName(GeneralName.dNSName, dns));
		}
		for (String uri : spec.uriSans()) {
			names.add(new GeneralName(GeneralName.uniformResourceIdentifier, uri));
		}
		return names.isEmpty() ? null : new GeneralNames(names.toArray(GeneralName[]::new));
	}

	private static X509Certificate convert(X509CertificateHolder holder) throws Exception {
		return new JcaX509CertificateConverter().getCertificate(holder);
	}

	/** Parse a DER-encoded X.509 certificate. */
	public static X509Certificate parse(byte[] der) {
		try {
			return (X509Certificate) CertificateFactory.getInstance("X.509")
					.generateCertificate(new java.io.ByteArrayInputStream(der));
		} catch (CertificateException e) {
			throw new IllegalArgumentException("failed to parse X.509 certificate", e);
		}
	}

	/**
	 * Build a PKIX {@link X509TrustManager} anchored on a single CA certificate —
	 * used by the {@code AuthInterceptor} to independently re-validate a presented
	 * client-cert chain against the internal CA (not relying solely on the TLS-layer
	 * toggle, per the trust model in VERSIONING.md §7).
	 */
	public static X509TrustManager trustManagerFor(X509Certificate caCertificate) {
		try {
			KeyStore trust = KeyStore.getInstance("PKCS12");
			trust.load(null, null);
			trust.setCertificateEntry("internal-mtls-ca", caCertificate);
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
			tmf.init(trust);
			for (var tm : tmf.getTrustManagers()) {
				if (tm instanceof X509TrustManager x509) {
					return x509;
				}
			}
			throw new IllegalStateException("no X509TrustManager produced for the internal mTLS CA");
		} catch (Exception e) {
			throw new IllegalStateException("failed to build the internal mTLS trust manager", e);
		}
	}

	/** A validity window backdated by {@code backdate} and running for {@code ttl}. */
	public static Instant[] validityWindow(Instant now, Duration backdate, Duration ttl) {
		return new Instant[]{now.minus(backdate), now.plus(ttl)};
	}
}
