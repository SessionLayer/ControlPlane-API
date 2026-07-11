package io.sessionlayer.controlplane.authz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/** Exact CIDR containment for the source-IP reducer (FR-AUTH-15). */
class CidrsTest {

	@Test
	void ipv4Containment() {
		assertThat(Cidrs.contains("10.0.0.0/8", "10.5.4.3")).isTrue();
		assertThat(Cidrs.contains("10.0.0.0/8", "11.0.0.1")).isFalse();
		assertThat(Cidrs.contains("192.168.1.0/24", "192.168.1.55")).isTrue();
		assertThat(Cidrs.contains("192.168.1.0/24", "192.168.2.1")).isFalse();
		assertThat(Cidrs.contains("0.0.0.0/0", "8.8.8.8")).isTrue();
		assertThat(Cidrs.contains("10.1.2.3/32", "10.1.2.3")).isTrue();
		assertThat(Cidrs.contains("10.1.2.3/32", "10.1.2.4")).isFalse();
	}

	@Test
	void ipv6Containment() {
		assertThat(Cidrs.contains("2001:db8::/32", "2001:db8:1234::1")).isTrue();
		assertThat(Cidrs.contains("2001:db8::/32", "2001:dead::1")).isFalse();
	}

	@Test
	void familyMismatchIsNotContained() {
		assertThat(Cidrs.contains("10.0.0.0/8", "2001:db8::1")).isFalse();
	}

	@Test
	void malformedCidrThrows() {
		assertThatThrownBy(() -> Cidrs.contains("10.0.0.0", "10.0.0.1")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> Cidrs.contains("10.0.0.0/40", "10.0.0.1"))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void hostnamesAreNeverResolved() {
		assertThat(Cidrs.isAddress("example.com")).isFalse();
		assertThat(Cidrs.isAddress("10.0.0.1")).isTrue();
		assertThat(Cidrs.isAddress("2001:db8::1")).isTrue();
	}
}
