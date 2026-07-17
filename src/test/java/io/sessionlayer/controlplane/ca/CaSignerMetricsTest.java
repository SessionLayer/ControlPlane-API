package io.sessionlayer.controlplane.ca;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.sessionlayer.controlplane.ca.CaSignerService.NoSignerAvailable;
import io.sessionlayer.controlplane.data.config.CaConfigRepository;
import io.sessionlayer.controlplane.data.runtime.CaKeyMaterialRepository;
import io.sessionlayer.controlplane.observability.SloMetrics;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * NFR-3: when no active CA of the requested kind exists, {@code activeSigner}
 * fails closed with {@link NoSignerAvailable} (never a wrong-key signer) AND
 * the availability SLI records the fail-closed as {@code outcome=unavailable} —
 * the "signer-down fails closed, measured" gate, without Docker.
 */
class CaSignerMetricsTest {

	@Test
	void noActiveSignerFailsClosedAndIsMeasuredUnavailable() {
		CaConfigRepository configs = mock(CaConfigRepository.class);
		CaKeyMaterialRepository keys = mock(CaKeyMaterialRepository.class);
		LocalCaFactory factory = mock(LocalCaFactory.class);
		when(configs.findByCaKindAndRotationState("session", "active")).thenReturn(Mono.empty());

		SimpleMeterRegistry registry = new SimpleMeterRegistry();
		CaSignerService service = new CaSignerService(configs, keys, factory, new SloMetrics(registry));

		StepVerifier.create(service.activeSigner("session")).expectError(NoSignerAvailable.class).verify();
		// A real request is measured under source=request (the NFR-3 SLI population).
		assertThat(registry.get("sessionlayer.ca.signer").tag("kind", "session").tag("source", "request")
				.tag("outcome", "unavailable").counter().count()).isEqualTo(1.0);

		// The health-probe poll is the SAME fail-closed but tagged source=probe, so it
		// never dilutes the request SLI (F-s21 SLI-population fix).
		StepVerifier.create(service.activeSigner("session", SloMetrics.SOURCE_PROBE))
				.expectError(NoSignerAvailable.class).verify();
		assertThat(registry.get("sessionlayer.ca.signer").tag("kind", "session").tag("source", "probe")
				.tag("outcome", "unavailable").counter().count()).isEqualTo(1.0);
	}
}
