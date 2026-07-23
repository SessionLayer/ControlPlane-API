package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TunnelAuditPolicyTest {

	@Test
	void wellFormedEntryPassesThrough() {
		TunnelAuditEntry entry = TunnelAuditPolicy
				.normalize(new TunnelAuditEntry("port_forward_local", "local", "db.internal:5432", 2048, 512, 30));
		assertThat(entry)
				.isEqualTo(new TunnelAuditEntry("port_forward_local", "local", "db.internal:5432", 2048, 512, 30));
	}

	// A non-forwarding capability (even a real one like shell) must not reach the
	// audit row's capabilities column or forge an action (the column CHECK would
	// roll back the whole finalize).
	@Test
	void capabilityOutsideTheForwardingVocabularyIsUnknown() {
		assertThat(TunnelAuditPolicy.normalize(new TunnelAuditEntry("shell", "local", "", 0, 0, 0)).capability())
				.isEqualTo(TunnelAuditPolicy.UNKNOWN);
		assertThat(TunnelAuditPolicy.normalize(new TunnelAuditEntry(null, "local", "", 0, 0, 0)).capability())
				.isEqualTo(TunnelAuditPolicy.UNKNOWN);
	}

	@Test
	void directionConstrainedTargetBoundedCountersClamped() {
		TunnelAuditEntry entry = TunnelAuditPolicy
				.normalize(new TunnelAuditEntry("x11", "sideways", "t".repeat(9000), -5, -1, -9));
		assertThat(entry.direction()).isEqualTo(TunnelAuditPolicy.UNKNOWN);
		assertThat(entry.target()).hasSize(512);
		assertThat(entry.bytesIn()).isZero();
		assertThat(entry.bytesOut()).isZero();
		assertThat(entry.durationSeconds()).isZero();
	}

	// Only `.closed` kinds exist — tunnel audit lands at finalize time, so no
	// synthetic live-looking `.opened` row is ever minted.
	@Test
	void actionMapsCapabilityToClosedKind() {
		assertThat(action("port_forward_local")).isEqualTo("port_forward.closed");
		assertThat(action("port_forward_remote")).isEqualTo("port_forward.closed");
		assertThat(action("x11")).isEqualTo("x11_forward.closed");
		assertThat(action("agent_forward")).isEqualTo("tunnel.unknown");
	}

	private static String action(String capability) {
		return TunnelAuditPolicy
				.action(TunnelAuditPolicy.normalize(new TunnelAuditEntry(capability, "local", "", 0, 0, 0)));
	}
}
