package io.sessionlayer.controlplane.security.mtls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.ca.mtls.LeafCertificateSpec;
import io.sessionlayer.controlplane.ca.mtls.LeafPurpose;
import io.sessionlayer.controlplane.ca.mtls.X509Certificates;
import io.sessionlayer.controlplane.security.AuthMethod;
import io.sessionlayer.controlplane.security.AuthenticatedPrincipal;
import io.sessionlayer.controlplane.security.RestAuthenticationToken;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.List;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.Test;
import org.springframework.http.server.reactive.SslInfo;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

/**
 * REST mTLS scheme (FR-AUTH-17): a valid internal-CA client cert → identity;
 * others rejected.
 */
class MtlsAuthenticationConverterTest {

	@Test
	void trustedClientCertificateResolvesIdentityFromUriSan() throws Exception {
		KeyPair ca = ec();
		X509Certificate caCert = X509Certificates.selfSignCa("test-ca", ca.getPublic(), ca.getPrivate(), BigInteger.ONE,
				Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
		KeyPair client = ec();
		X509Certificate leaf = X509Certificates.issueLeaf(caCert, ca.getPrivate(),
				new LeafCertificateSpec(client.getPublic(), "operator", List.of(),
						List.of("sessionlayer://operator/admin-1"), LeafPurpose.CLIENT, BigInteger.TWO,
						Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600)));

		MtlsAuthenticationConverter converter = converterTrusting(caCert);
		Authentication auth = converter.convert(exchangeWith(leaf)).block();

		assertThat(auth).isInstanceOf(RestAuthenticationToken.class);
		AuthenticatedPrincipal principal = (AuthenticatedPrincipal) auth.getPrincipal();
		assertThat(principal.identity()).isEqualTo("sessionlayer://operator/admin-1");
		assertThat(principal.method()).isEqualTo(AuthMethod.MTLS);
	}

	@Test
	void untrustedClientCertificateIsRejected() throws Exception {
		KeyPair ca = ec();
		X509Certificate caCert = X509Certificates.selfSignCa("test-ca", ca.getPublic(), ca.getPrivate(), BigInteger.ONE,
				Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
		// A self-signed cert NOT chained to the trusted CA.
		KeyPair rogue = ec();
		X509Certificate rogueCert = X509Certificates.selfSignCa("rogue", rogue.getPublic(), rogue.getPrivate(),
				BigInteger.TEN, Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

		MtlsAuthenticationConverter converter = converterTrusting(caCert);
		assertThat(converter.convert(exchangeWith(rogueCert)).blockOptional()).isEmpty();
	}

	@Test
	void noClientCertificateIsEmpty() {
		MtlsAuthenticationConverter converter = converterTrusting(null);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/v1/pins"));
		assertThat(converter.convert(exchange).blockOptional()).isEmpty();
	}

	private static MtlsAuthenticationConverter converterTrusting(X509Certificate caCert) {
		InternalCaTrustManagerProvider provider = mock(InternalCaTrustManagerProvider.class);
		if (caCert != null) {
			X509TrustManager tm = X509Certificates.trustManagerFor(caCert);
			when(provider.trustManager()).thenReturn(Mono.just(tm));
		}
		return new MtlsAuthenticationConverter(provider);
	}

	private static MockServerWebExchange exchangeWith(X509Certificate leaf) {
		SslInfo sslInfo = new SslInfo() {
			@Override
			public String getSessionId() {
				return "test-session";
			}

			@Override
			public X509Certificate[] getPeerCertificates() {
				return new X509Certificate[]{leaf};
			}
		};
		return MockServerWebExchange.from(MockServerHttpRequest.get("/v1/pins").sslInfo(sslInfo));
	}

	private static KeyPair ec() throws Exception {
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(new ECGenParameterSpec("secp256r1"));
		return gen.generateKeyPair();
	}
}
