package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;
import reactor.core.publisher.Mono;

/**
 * The cached WORM health indicator reports the store's true reachability:
 * reachable → UP, down → OUT_OF_SERVICE. Readiness participation is a separate,
 * opt-in concern (WormReadinessIncludeIT).
 */
class WormHealthIndicatorTest {

	@Test
	void reachableStoreIsUp() {
		WormObjectStore worm = mock(WormObjectStore.class);
		when(worm.probe()).thenReturn(Mono.empty());
		WormHealthIndicator indicator = new WormHealthIndicator(worm);
		assertThat(indicator.health().block().getStatus()).isEqualTo(Status.UP);
	}

	@Test
	void downStoreIsOutOfService() {
		WormObjectStore worm = mock(WormObjectStore.class);
		when(worm.probe()).thenReturn(Mono.error(new IllegalStateException("connection refused")));
		WormHealthIndicator indicator = new WormHealthIndicator(worm);
		assertThat(indicator.health().block().getStatus()).isEqualTo(Status.OUT_OF_SERVICE);
	}
}
