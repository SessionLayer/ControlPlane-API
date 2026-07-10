package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * FR-CA-4 capability/algorithm validation (rejected at validation, not
 * signing).
 */
class CaBackendCapabilitiesTest {

	@Test
	void p256IsProducibleByEveryBackend() {
		for (String backend : new String[]{"local", "aws_kms", "azure_keyvault", "vault"}) {
			assertThatCode(() -> CaBackendCapabilities.validate(backend, "ecdsa-p256")).doesNotThrowAnyException();
		}
	}

	@Test
	void onlyLocalAdvertisesTheWiderCurves() {
		// Local derives the digest from the curve; the cloud backends currently hash
		// with
		// SHA-256 only, so they advertise P-256 alone (F-cacloud-1).
		assertThatCode(() -> CaBackendCapabilities.validate("local", "ecdsa-p384")).doesNotThrowAnyException();
		assertThatThrownBy(() -> CaBackendCapabilities.validate("aws_kms", "ecdsa-p384"))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);
		assertThatThrownBy(() -> CaBackendCapabilities.validate("azure_keyvault", "ecdsa-p521"))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);
	}

	@Test
	void nonEcdsaAlgorithmsAreRejected() {
		assertThatThrownBy(() -> CaBackendCapabilities.validate("azure_keyvault", "ed25519"))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);
		assertThatThrownBy(() -> CaBackendCapabilities.validate("local", "rsa-4096"))
				.isInstanceOf(CaBackendCapabilities.AlgorithmNotSupported.class);
	}

	@Test
	void unknownBackendIsRejected() {
		assertThatThrownBy(() -> CaBackendCapabilities.validate("sqlite", "ecdsa-p256"))
				.isInstanceOf(IllegalArgumentException.class);
	}
}
