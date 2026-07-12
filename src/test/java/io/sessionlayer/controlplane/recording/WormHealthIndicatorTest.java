package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;
import reactor.core.publisher.Mono;

/**
 * The cached WORM readiness indicator: reachable → UP, down → OUT_OF_SERVICE,
 * gate-off → UP.
 */
class WormHealthIndicatorTest {

	private static WormProperties props(boolean readinessGate) {
		WormProperties properties = new WormProperties();
		properties.setReadinessGate(readinessGate);
		return properties;
	}

	@Test
	void reachableStoreIsUp() {
		WormObjectStore worm = mock(WormObjectStore.class);
		when(worm.probe()).thenReturn(Mono.empty());
		WormHealthIndicator indicator = new WormHealthIndicator(worm, props(true));
		assertThat(indicator.health().block().getStatus()).isEqualTo(Status.UP);
	}

	@Test
	void downStoreIsOutOfService() {
		WormObjectStore worm = mock(WormObjectStore.class);
		when(worm.probe()).thenReturn(Mono.error(new IllegalStateException("connection refused")));
		WormHealthIndicator indicator = new WormHealthIndicator(worm, props(true));
		assertThat(indicator.health().block().getStatus()).isEqualTo(Status.OUT_OF_SERVICE);
	}

	@Test
	void gateDisabledAlwaysReadsUpWithoutProbing() {
		WormObjectStore worm = mock(WormObjectStore.class); // probe() never stubbed → must not be called
		WormHealthIndicator indicator = new WormHealthIndicator(worm, props(false));
		assertThat(indicator.health().block().getStatus()).isEqualTo(Status.UP);
	}
}
