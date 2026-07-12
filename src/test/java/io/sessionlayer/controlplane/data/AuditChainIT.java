package io.sessionlayer.controlplane.data;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.audit.AuditChainVerifier;
import io.sessionlayer.controlplane.audit.AuditWriter;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import io.sessionlayer.controlplane.data.runtime.AuditEventRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The {@code audit_event} tamper-evidence hash chain (Design §12.2 baseline,
 * FR-AUD-3). Every {@link AuditWriter} write links into a per-{@code seq}
 * SHA-256 chain; {@link AuditChainVerifier} recomputes it. This proves the two
 * properties the append-only WORM table cannot prove alone — no row's content
 * was altered, and no row was removed/reordered — so an adversary who somehow
 * bypassed the append-only trigger still leaves a detectable break (§15).
 */
class AuditChainIT extends AbstractDataIT {

	@Autowired
	private AuditWriter audit;

	@Autowired
	private AuditEventRepository audits;

	@Test
	void writesLinkIntoAVerifiableChain() {
		UUID session = UUID.randomUUID();
		for (int i = 0; i < 5; i++) {
			audit.record("alice@corp", "node-" + i, "chain.probe", "success", session, UUID.randomUUID(),
					Map.of("i", Integer.toString(i))).block();
		}
		List<AuditEvent> chain = audits.findChainOrdered().collectList().block();
		assertThat(chain).isNotEmpty();
		assertThat(chain).allSatisfy(e -> {
			assertThat(e.recordHash()).isNotNull();
			assertThat(e.prevHash()).isNotNull();
		});
		AuditChainVerifier.Result result = AuditChainVerifier.verify(chain);
		assertThat(result.valid()).as("recomputed chain: %s", result.failure()).isTrue();
	}

	@Test
	void aMutatedRowBreaksTheChain() {
		audit.record("mallory@corp", "node-x", "chain.mutate", "success", UUID.randomUUID(), null, Map.of("k", "v"))
				.block();
		List<AuditEvent> chain = audits.findChainOrdered().collectList().block();
		assertThat(AuditChainVerifier.verify(chain).valid()).isTrue();

		// Silently rewriting a field (as a compromised operator bypassing the trigger
		// would) but keeping the stored hashes leaves record_hash committing to the
		// ORIGINAL content — detected on recompute.
		List<AuditEvent> tampered = new ArrayList<>(chain);
		AuditEvent v = tampered.get(tampered.size() - 1);
		AuditEvent mutated = new AuditEvent(v.id(), v.occurredAt(), "TAMPERED", v.subject(), v.action(), v.outcome(),
				v.correlationId(), v.sessionId(), v.nodeId(), v.nodeLabels(), v.sourceIp(), v.accessModel(),
				v.capabilities(), v.detail(), v.prevHash(), v.recordHash(), v.version(), v.createdAt());
		tampered.set(tampered.size() - 1, mutated);
		AuditChainVerifier.Result result = AuditChainVerifier.verify(tampered);
		assertThat(result.valid()).isFalse();
		assertThat(result.failure()).contains("record_hash mismatch");
	}

	@Test
	void aRemovedRowBreaksTheChain() {
		for (int i = 0; i < 3; i++) {
			audit.record("carol@corp", null, "chain.remove", "success", UUID.randomUUID(), null, Map.of()).block();
		}
		List<AuditEvent> chain = audits.findChainOrdered().collectList().block();
		assertThat(chain.size()).isGreaterThanOrEqualTo(3);
		assertThat(AuditChainVerifier.verify(chain).valid()).isTrue();

		// Excising a row snaps its successor's prev_hash link (the successor still
		// commits to the removed row's record_hash).
		List<AuditEvent> excised = new ArrayList<>(chain);
		excised.remove(excised.size() - 2);
		AuditChainVerifier.Result result = AuditChainVerifier.verify(excised);
		assertThat(result.valid()).isFalse();
		assertThat(result.failure()).contains("prev_hash link broken");
	}
}
