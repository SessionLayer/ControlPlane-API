package io.sessionlayer.controlplane.device;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.auth.Secrets;
import io.sessionlayer.controlplane.data.runtime.DeviceFlowRepository;
import io.sessionlayer.controlplane.support.AbstractAuthIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.r2dbc.core.DatabaseClient;

/**
 * Device-flow state machine + source-context correlation (FR-AUTH-3, §5.2). The
 * IdP-resolved identity is injected via {@link DeviceFlowService#approve} (the
 * OIDC RP round-trip is proven separately against the oidc-mock); here the
 * lifecycle, the approving-browser correlation, the timeout, and the poll are
 * proven deterministically.
 */
class DeviceFlowIT extends AbstractAuthIT {

	@Autowired
	DeviceFlowService deviceFlowService;
	@Autowired
	DeviceFlowRepository deviceFlows;
	@Autowired
	DatabaseClient db;

	@Test
	void lifecycleApprovedFromMatchingSource() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("198.51.100.7", "conn-1").block();
		assertThat(begun).isNotNull();
		// Codes are stored hashed, never raw.
		String storedDeviceHash = deviceFlows.findById(begun.deviceFlowId()).block().deviceCodeHash();
		assertThat(storedDeviceHash).isEqualTo(Secrets.sha256Hex(begun.deviceCode()));

		// Pending before approval.
		assertThat(deviceFlowService.poll(begun.deviceCode()).block().status()).isEqualTo("pending");

		// Approve from the same source → authorized + source-context match true.
		deviceFlowService.approve(begun.deviceFlowId(), "alice@example.com", "198.51.100.7").block();
		DeviceFlowService.Status status = deviceFlowService.poll(begun.deviceCode()).block();
		assertThat(status.status()).isEqualTo("authorized");
		assertThat(status.identity()).isEqualTo("alice@example.com");
		assertThat(status.sourceContextMatch()).isTrue();
	}

	@Test
	void mismatchedSourceIsFlaggedButStillApprovesByDefault() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("198.51.100.7", null).block();
		deviceFlowService.approve(begun.deviceFlowId(), "bob@example.com", "203.0.113.200").block();
		DeviceFlowService.Status status = deviceFlowService.poll(begun.deviceCode()).block();
		assertThat(status.status()).isEqualTo("authorized"); // flag-only default (deny-only reducer, FR-AUTH-15)
		assertThat(status.sourceContextMatch()).isFalse();
	}

	@Test
	void timeoutExpiresAPendingFlow() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("198.51.100.7", null).block();
		db.sql("UPDATE runtime.device_flow SET expires_at = now() - interval '1 minute' WHERE id=:id")
				.bind("id", begun.deviceFlowId()).fetch().rowsUpdated().block();
		assertThat(deviceFlowService.poll(begun.deviceCode()).block().status()).isEqualTo("expired");
	}

	@Test
	void unknownDeviceCodePollsEmpty() {
		assertThat(deviceFlowService.poll(Secrets.randomToken(32)).blockOptional()).isEmpty();
	}

	@Test
	void pendingLookupByUserCode() {
		DeviceFlowService.Begun begun = deviceFlowService.begin("198.51.100.7", null).block();
		// The verification page finds the pending flow by user code (deviceCode is
		// separate).
		assertThat(deviceFlowService.pendingByUserCode(userCodeFor(begun)).blockOptional()).isPresent();
	}

	// The user code is not returned by poll; recover it via the stored hash for the
	// lookup test.
	private String userCodeFor(DeviceFlowService.Begun begun) {
		return begun.userCode();
	}
}
