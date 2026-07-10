package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.runtime.AgentIdentity;
import io.sessionlayer.controlplane.data.runtime.AgentIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentity;
import io.sessionlayer.controlplane.data.runtime.GatewayIdentityRepository;
import io.sessionlayer.controlplane.data.runtime.Node;
import io.sessionlayer.controlplane.data.runtime.NodeRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.OptimisticLockingFailureException;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

/**
 * Generation-counter semantics (Design §8.2). Two guards are proven:
 * <ol>
 * <li>the {@code @Version} optimistic lock makes a stale concurrent renewal
 * fail ({@link OptimisticLockingFailureException}) instead of silently
 * racing;</li>
 * <li>a DB {@code BEFORE UPDATE} trigger rejects any update that
 * <b>decreases</b> the generation counter
 * ({@link DataIntegrityViolationException}).</li>
 * </ol>
 */
class GenerationCounterIT extends AbstractDataIT {

	@Autowired
	private NodeRepository nodes;

	@Autowired
	private AgentIdentityRepository agentIdentities;

	@Autowired
	private GatewayIdentityRepository gatewayIdentities;

	@Autowired
	private ObjectMapper objectMapper;

	private AgentIdentity withGeneration(AgentIdentity src, long generation) {
		return new AgentIdentity(src.id(), src.nodeId(), src.mtlsIdentityRef(), src.fingerprint(), generation,
				src.joinMethod(), src.status(), src.issuedAt(), src.notAfter(), src.version(), src.createdAt(),
				src.updatedAt());
	}

	@Test
	void staleRenewalFailsOptimisticLock() {
		var node = nodes.save(Node.create("node-optlock", null, objectMapper.readTree("{}"), "agent", "active",
				"healthy", null, null)).block();
		var saved = agentIdentities.save(AgentIdentity.create(node.id(), "ref", null, 0, "token", "active", null, null))
				.block();

		// two independently-loaded copies with the same version (a renewal race)
		var copyA = agentIdentities.findById(saved.id()).block();
		var copyB = agentIdentities.findById(saved.id()).block();

		var winner = agentIdentities.save(withGeneration(copyA, 1)).block(); // increments version
		assertThat(winner.generation()).isEqualTo(1);

		// copyB carries the now-stale version -> its update matches no row
		StepVerifier.create(agentIdentities.save(withGeneration(copyB, 1)))
				.verifyError(OptimisticLockingFailureException.class);
	}

	@Test
	void decreasingGenerationRejectedByTrigger() {
		var node = nodes.save(Node.create("node-monotonic", null, objectMapper.readTree("{}"), "agent", "active",
				"healthy", null, null)).block();
		var saved = agentIdentities.save(AgentIdentity.create(node.id(), "ref", null, 5, "token", "active", null, null))
				.block();

		// same (current) version -> passes the optimistic check, but the trigger
		// rejects 5 -> 4
		StepVerifier.create(agentIdentities.save(withGeneration(saved, 4)))
				.verifyError(DataIntegrityViolationException.class);
	}

	@Test
	void increasingGenerationAllowed() {
		var node = nodes.save(Node.create("node-increase", null, objectMapper.readTree("{}"), "agent", "active",
				"healthy", null, null)).block();
		var saved = agentIdentities.save(AgentIdentity.create(node.id(), "ref", null, 5, "token", "active", null, null))
				.block();
		var renewed = agentIdentities.save(withGeneration(saved, 6)).block();
		assertThat(renewed.generation()).isEqualTo(6);
	}

	@Test
	void gatewayGenerationAlsoMonotonic() {
		var saved = gatewayIdentities
				.save(GatewayIdentity.create("gw-monotonic", "ref", null, 3, "mtls", "active", null, null)).block();
		var decreased = new GatewayIdentity(saved.id(), saved.name(), saved.mtlsIdentityRef(), saved.fingerprint(), 2,
				saved.joinMethod(), saved.status(), saved.issuedAt(), saved.notAfter(), saved.version(),
				saved.createdAt(), saved.updatedAt());
		StepVerifier.create(gatewayIdentities.save(decreased)).verifyError(DataIntegrityViolationException.class);
	}
}
