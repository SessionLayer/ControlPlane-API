package io.sessionlayer.controlplane.web;

import io.sessionlayer.controlplane.config.ComponentDescriptor;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Fast, DB-free coverage of the contract-first meta probes via a standalone
 * WebFlux binding (no Spring context). The full-context/real-DB path is covered
 * by {@code ControlPlaneSmokeIT}.
 */
class MetaControllerTest {

	private final WebTestClient client = WebTestClient
			.bindToController(new MetaController(new ComponentDescriptor("0.1.0"))).build();

	@Test
	void healthzReportsPass() {
		client.get().uri("/v1/healthz").exchange().expectStatus().isOk().expectBody().jsonPath("$.status")
				.isEqualTo("pass");
	}

	@Test
	void versionReportsComponentVersionAndProtocolRanges() {
		client.get().uri("/v1/version").exchange().expectStatus().isOk().expectBody().jsonPath("$.component")
				.isEqualTo("SessionLayer Control Plane").jsonPath("$.version").isEqualTo("0.1.0")
				.jsonPath("$.protocols.controlPlaneGatewayGrpc.min").isEqualTo("1.0")
				.jsonPath("$.protocols.controlPlaneGatewayGrpc.max").isEqualTo("1.0")
				.jsonPath("$.protocols.agentGatewayWire.min").isEqualTo("1.0")
				.jsonPath("$.protocols.agentGatewayWire.max").isEqualTo("1.0");
	}
}
