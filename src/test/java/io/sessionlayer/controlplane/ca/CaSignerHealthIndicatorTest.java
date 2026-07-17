package io.sessionlayer.controlplane.ca;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.sessionlayer.controlplane.ca.CaSignerService.NoSignerAvailable;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * NFR-3 health peer: UP while an active session signer resolves, OUT_OF_SERVICE
 * on the fail-closed state (no active signer) — for {@code /actuator/health}
 * alerting, without gating readiness.
 */
class CaSignerHealthIndicatorTest {

	@Test
	void reportsUpWhenASignerIsAvailable() {
		CaSignerService signers = mock(CaSignerService.class);
		when(signers.activeSigner("session")).thenReturn(Mono.just(mock(SshCertSigner.class)));

		StepVerifier.create(new CaSignerHealthIndicator(signers).health())
				.assertNext(health -> org.assertj.core.api.Assertions.assertThat(health.getStatus())
						.isEqualTo(Status.UP))
				.verifyComplete();
	}

	@Test
	void reportsOutOfServiceWhenSignerDown() {
		CaSignerService signers = mock(CaSignerService.class);
		when(signers.activeSigner("session")).thenReturn(Mono.error(new NoSignerAvailable("no active session CA")));

		StepVerifier.create(new CaSignerHealthIndicator(signers).health())
				.assertNext(health -> org.assertj.core.api.Assertions.assertThat(health.getStatus())
						.isEqualTo(Status.OUT_OF_SERVICE))
				.verifyComplete();
	}
}
