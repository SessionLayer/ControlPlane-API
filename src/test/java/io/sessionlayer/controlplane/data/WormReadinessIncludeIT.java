package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroups;
import org.springframework.test.context.TestPropertySource;

/**
 * The WORM readiness opt-in: adding {@code worm} to the standard Boot readiness
 * group include makes the (enabled) WORM contributor participate in readiness —
 * so a down store deregisters the CP. Proves the opt-in path an operator uses
 * for a per-CP/node-local store; the default (worm observable but NOT in
 * readiness) is covered by {@code ControlPlaneSmokeIT}.
 */
@TestPropertySource(properties = "management.endpoint.health.group.readiness.include=readinessState,worm")
class WormReadinessIncludeIT extends AbstractDataIT {

	@Autowired
	private HealthEndpointGroups groups;

	@Test
	void wormJoinsReadinessWhenIncluded() {
		assertThat(groups.get("readiness")).isNotNull();
		assertThat(groups.get("readiness").isMember("worm")).isTrue();
	}
}
