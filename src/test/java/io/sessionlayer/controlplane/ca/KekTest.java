package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.sessionlayer.controlplane.ca.backend.local.Kek;
import io.sessionlayer.controlplane.ca.backend.local.KekProvider;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * KEK fail-closed default (F-ca-kek-default-1) + AAD context binding
 * (F-ca-kek-aad-1): the dev default must not silently protect production, and a
 * wrapped CA key must not be liftable into a different CA's row.
 */
class KekTest {

	private static final String REAL_KEK = Base64.getEncoder()
			.encodeToString("a-real-32-byte-production-kek!!!".getBytes(StandardCharsets.UTF_8));

	@Test
	void devDefaultKekFailsClosedUnlessExplicitlyAllowed() {
		// Unset KEK -> dev default -> refuse to start without the opt-in.
		assertThatThrownBy(() -> new KekProvider("", null, false)).isInstanceOf(IllegalStateException.class)
				.hasMessageContaining("refusing to start");
		// Same, detected by decoded bytes even if the dev key is re-encoded.
		assertThatThrownBy(() -> new KekProvider(KekProvider.DEV_DEFAULT_KEK_BASE64, null, false))
				.isInstanceOf(IllegalStateException.class);
		// Opt-in permits it (dev/test only).
		assertThatCode(() -> new KekProvider("", null, true)).doesNotThrowAnyException();
		// A real KEK always boots and is not flagged as the dev default.
		KekProvider real = new KekProvider(REAL_KEK, null, false);
		assertThat(real.isDevDefault()).isFalse();
		assertThat(real.reference()).isEqualTo("config:sessionlayer.ca.local.kek-base64");
	}

	@Test
	void aadBindsCiphertextToItsContext() {
		Kek kek = new KekProvider(REAL_KEK, null, false).newKek();
		byte[] plaintext = "ca-private-key-bytes".getBytes(StandardCharsets.UTF_8);
		byte[] aadA = "config-A|ecdsa-sha2-nistp256|ref".getBytes(StandardCharsets.UTF_8);
		byte[] aadB = "config-B|ecdsa-sha2-nistp256|ref".getBytes(StandardCharsets.UTF_8);

		Kek.Wrapped wrapped = kek.wrap(plaintext, aadA);
		assertThat(kek.unwrap(wrapped.iv(), wrapped.ciphertext(), aadA)).isEqualTo(plaintext);
		// Unwrapping with a different CA's AAD fails closed (cross-CA substitution
		// blocked).
		assertThatThrownBy(() -> kek.unwrap(wrapped.iv(), wrapped.ciphertext(), aadB))
				.isInstanceOf(IllegalStateException.class);
		kek.destroy();
	}
}
