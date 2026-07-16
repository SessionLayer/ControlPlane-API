package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.audit.AuditChainVerifier;
import io.sessionlayer.controlplane.audit.AuditEventStore;
import io.sessionlayer.controlplane.audit.AuditForwarder;
import io.sessionlayer.controlplane.audit.CapturingAuditForwarder;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

/**
 * Proves the pluggable audit exporter seam (owner requirement, §15/NFR-5):
 * substituting a second {@link AuditForwarder} implementation shows the store
 * ships every committed event off-box through the interface — not a hardcoded
 * backend. The double also proves the "forward AFTER commit" contract (the
 * forwarded event already carries the chain hashes) and that a forward never
 * disturbs the primary of record.
 */
class AuditForwarderSeamIT extends AbstractDataIT {

	@TestConfiguration
	static class Doubles {
		// A bean of type AuditForwarder suppresses the default @ConditionalOnMissingBean
		// log forwarder, so the real store forwards through THIS impl.
		@Bean
		CapturingAuditForwarder capturingAuditForwarder() {
			return new CapturingAuditForwarder();
		}
	}

	@Autowired
	private AuditEventStore audit;

	@Autowired
	private AuditEventRepository audits;

	@Autowired
	private CapturingAuditForwarder forwarder;

	@Test
	void everyCommittedEventIsShippedOffBoxThroughTheSwappedForwarder() {
		UUID session = UUID.randomUUID();
		audit.record("alice@corp", "node-1", "seam.forward", "success", session, null, Map.of("k", "v")).block();

		List<AuditEvent> forwarded = forwarder.captured().stream().filter(e -> "seam.forward".equals(e.action()))
				.toList();
		assertThat(forwarded).hasSize(1);
		// Forwarded AFTER commit: the shipped event already carries the chain hashes.
		assertThat(forwarded.getFirst().recordHash()).isNotNull();
		assertThat(forwarded.getFirst().actor()).isEqualTo("alice@corp");

		// The primary of record is intact and still chain-verifiable (forwarding is a
		// side channel that never mutates the store).
		List<AuditEvent> chain = audits.findChainOrdered().collectList().block();
		assertThat(chain).anyMatch(e -> "seam.forward".equals(e.action()));
		assertThat(AuditChainVerifier.verify(chain).valid()).isTrue();
	}
}
