package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.data.config.OperatorSettingsRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

/**
 * FR-SESS-3 — the cluster-default concurrent-session cap is settable via
 * standard deployment config, not DB-only. The
 * {@code sessionlayer.session-limits.default-max-concurrent} property is
 * reconciled into {@code operator_settings.default_max_concurrent_sessions} at
 * bootstrap; the Authorize path then enforces that operator default (the
 * enforcement-of-default is proven by {@code ConcurrentSessionLimitIT}). The
 * knob is opt-in: unset ⇒ the stored value is left untouched (null ⇒
 * unlimited).
 */
@TestPropertySource(properties = "sessionlayer.session-limits.default-max-concurrent=7")
class SessionLimitConfigBindingIT extends AbstractMtlsIT {

	@Autowired
	private OperatorSettingsRepository operatorSettings;

	// Restore the shared singleton so other ITs (which share this Postgres) see the
	// null/unlimited default.
	@AfterEach
	void resetClusterDefault() {
		db.sql("UPDATE config.operator_settings SET default_max_concurrent_sessions = NULL WHERE singleton = true")
				.fetch().rowsUpdated().block();
	}

	@Test
	void deploymentConfigSeedsTheClusterDefaultIntoOperatorSettings() {
		assertThat(operatorSettings.findSingleton().block().defaultMaxConcurrentSessions()).isEqualTo(7);
	}
}
