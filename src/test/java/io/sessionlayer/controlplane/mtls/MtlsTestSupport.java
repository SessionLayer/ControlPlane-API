package io.sessionlayer.controlplane.mtls;

import io.grpc.ManagedChannel;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.sessionlayer.controlplane.ca.CaKeyType;
import io.sessionlayer.controlplane.ca.key.SshEcdsaPublicKeys;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * Static helpers for the mTLS ITs playing the Gateway (client) side: keypairs,
 * PKCS#10 CSRs, OpenSSH inner-leg public-key blobs, and grpc-netty client
 * channels (mTLS or plaintext). No Spring context needed.
 */
public final class MtlsTestSupport {

	private MtlsTestSupport() {
	}

	/** A fresh ECDSA P-256 keypair (the Gateway generates its own keys — D2). */
	public static KeyPair generateEcKeyPair() {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			generator.initialize(new ECGenParameterSpec("secp256r1"));
			return generator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}

	/** A DER PKCS#10 CSR for {@code keyPair} with subject {@code CN=commonName}. */
	public static byte[] csr(KeyPair keyPair, String commonName) {
		try {
			var subject = new org.bouncycastle.asn1.x500.X500Name("CN=" + commonName);
			var builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
			ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
			return builder.build(signer).getEncoded();
		} catch (Exception e) {
			throw new IllegalStateException("failed to build test CSR", e);
		}
	}

	/** The OpenSSH wire ECDSA-P256 public-key blob for an inner-leg subject key. */
	public static byte[] opensshPublicKeyBlob(ECPublicKey publicKey) {
		return SshEcdsaPublicKeys.encode(publicKey, CaKeyType.ECDSA_NISTP256);
	}

	/**
	 * A TLS-1.3 client SslContext trusting {@code caCertificate}; if
	 * {@code clientLeaf}/{@code clientKey} are provided it presents that client
	 * cert (mTLS), otherwise it connects without one (the bootstrap case).
	 */
	public static SslContext clientSslContext(X509Certificate caCertificate, X509Certificate clientLeaf,
			PrivateKey clientKey) {
		try {
			SslContextBuilder builder = GrpcSslContexts.forClient().trustManager(caCertificate);
			builder.protocols("TLSv1.3");
			if (clientLeaf != null && clientKey != null) {
				builder.keyManager(clientKey, clientLeaf);
			}
			return builder.build();
		} catch (Exception e) {
			throw new IllegalStateException("failed to build client SslContext", e);
		}
	}

	/**
	 * A client SslContext that offers ONLY TLS 1.2 — used to assert the
	 * TLS-1.3-only server refuses it (L2). Trusts {@code caCertificate}; presents
	 * no client cert.
	 */
	public static SslContext tls12ClientContext(X509Certificate caCertificate) {
		try {
			return GrpcSslContexts.forClient().trustManager(caCertificate).protocols("TLSv1.2").build();
		} catch (Exception e) {
			throw new IllegalStateException("failed to build TLS-1.2 client SslContext", e);
		}
	}

	/** An mTLS channel to the CP server on {@code localhost:port}. */
	public static ManagedChannel channel(int port, SslContext sslContext) {
		return NettyChannelBuilder.forAddress("localhost", port).sslContext(sslContext).overrideAuthority("localhost")
				.build();
	}

	/**
	 * A PLAINTEXT channel (used to prove the TLS-only server refuses plaintext).
	 */
	public static ManagedChannel plaintextChannel(int port) {
		return NettyChannelBuilder.forAddress("localhost", port).usePlaintext().build();
	}
}
