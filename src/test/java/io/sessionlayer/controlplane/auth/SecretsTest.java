package io.sessionlayer.controlplane.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SecretsTest {

	@Test
	void sha256IsDeterministicAndHex() {
		assertThat(Secrets.sha256Hex("abc")).isEqualTo(Secrets.sha256Hex("abc")).hasSize(64).matches("[0-9a-f]+");
		assertThat(Secrets.sha256Hex("abc")).isNotEqualTo(Secrets.sha256Hex("abd"));
	}

	@Test
	void constantTimeEqualsMatchesOnlyEqualStrings() {
		assertThat(Secrets.constantTimeEquals("token-abc", "token-abc")).isTrue();
		assertThat(Secrets.constantTimeEquals("token-abc", "token-abd")).isFalse();
		assertThat(Secrets.constantTimeEquals("token-abc", "token-abcd")).isFalse();
		assertThat(Secrets.constantTimeEquals(null, "x")).isFalse();
	}

	@Test
	void otpHasAtLeast128BitsOfEntropyAndIsBase32() {
		String otp = Secrets.randomBase32(16); // 16 bytes = 128 bits
		assertThat(otp).matches("[A-Z2-7]+");
		assertThat(otp.length()).isGreaterThanOrEqualTo(25); // 128 bits / 5 bits-per-char ≈ 26
	}

	@Test
	void randomTokensAreUniqueAndUrlSafe() {
		Set<String> seen = new HashSet<>();
		for (int i = 0; i < 1000; i++) {
			String token = Secrets.randomToken(24);
			assertThat(token).matches("[A-Za-z0-9_-]+");
			assertThat(seen.add(token)).isTrue();
		}
	}

	@Test
	void userCodeIsGroupedAndTyped() {
		assertThat(Secrets.randomUserCode()).matches("[A-Z2-7]{4}-[A-Z2-7]{4}");
	}
}
