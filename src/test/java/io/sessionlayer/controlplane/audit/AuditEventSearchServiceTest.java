package io.sessionlayer.controlplane.audit;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.audit.AuditEventStore.AuditPage;
import io.sessionlayer.controlplane.audit.AuditEventStore.AuditQuery;
import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The Part B search service works over the {@link AuditEventStore} interface,
 * not the Postgres backend — proven by swapping in the
 * {@link InMemoryAuditEventStore} double (owner extensibility requirement). No
 * Spring context / Docker: pure interface wiring.
 */
class AuditEventSearchServiceTest {

	private AuditQuery query(String action) {
		return new AuditQuery(null, null, action, null, null, null, null, null, null, null, null, Map.of(), null,
				List.of(), null, 50);
	}

	@Test
	void searchReturnsWhatWasRecordedThroughTheInterface() {
		InMemoryAuditEventStore store = new InMemoryAuditEventStore();
		AuditEventSearchService service = new AuditEventSearchService(store);
		for (int i = 0; i < 3; i++) {
			store.record("alice", "node-" + i, "probe.run", "success", UUID.randomUUID(), UUID.randomUUID(),
					Map.of("i", Integer.toString(i))).block();
		}

		AuditPage page = service.search(query("probe.run"), "admin").block();
		assertThat(page.items()).hasSize(3).allSatisfy(e -> assertThat(e.action()).isEqualTo("probe.run"));

		// The access itself is audited (FR-PADM-3): one audit.search appended.
		assertThat(service.search(query("audit.search"), "admin").block().items()).isNotEmpty();
	}

	@Test
	void getReturnsTheEventAndAuditsTheAccess() {
		InMemoryAuditEventStore store = new InMemoryAuditEventStore();
		AuditEventSearchService service = new AuditEventSearchService(store);
		store.record("bob", "node", "probe.get", "success", null, null, Map.of()).block();
		AuditEvent seeded = store.search(query("probe.get")).block().items().get(0);

		AuditEvent got = service.get(seeded.id(), "admin").block();
		assertThat(got.id()).isEqualTo(seeded.id());
		assertThat(service.search(query("audit.get"), "admin").block().items()).isNotEmpty();
	}

	@Test
	void readsLeaveTheChainVerifiable() {
		InMemoryAuditEventStore store = new InMemoryAuditEventStore();
		AuditEventSearchService service = new AuditEventSearchService(store);
		store.record("carol", null, "probe.chain", "success", null, null, Map.of()).block();
		assertThat(store.verifyChain().block().valid()).isTrue();

		service.search(query("probe.chain"), "admin").block();
		assertThat(store.verifyChain().block().valid()).isTrue();
	}
}
