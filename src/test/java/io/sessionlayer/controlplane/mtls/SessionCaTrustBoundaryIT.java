package io.sessionlayer.controlplane.mtls;

import static org.assertj.core.api.Assertions.assertThat;

import io.sessionlayer.controlplane.ca.CaRotationService;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * FR-CA-2 (Design §3.2/§8.3, invariant I1) — the node trusts ONLY the internal
 * session CA, and a break-glass/incident CA is NEVER a standing entry in the
 * node's {@code TrustedUserCAKeys}. Asserts directly that the session-kind
 * trust set handed to the node is non-empty and disjoint from the host and user
 * CA kinds, that there is no break-glass CA kind at all (the incident CA is a
 * non-standing last resort — never provisioned into standing trust), so the
 * session trust set can never carry it.
 */
class SessionCaTrustBoundaryIT extends AbstractMtlsIT {

	@Autowired
	private CaRotationService caRotation;

	@Test
	void theNodeTrustsOnlyTheSessionCaAndNeverAStandingBreakGlassCa() {
		List<String> sessionTrust = caRotation.trustedCaKeys("session").block();
		List<String> hostTrust = caRotation.trustedCaKeys("host").block();
		List<String> userTrust = caRotation.trustedCaKeys("user").block();
		List<String> breakglassTrust = caRotation.trustedCaKeys("breakglass").block();

		// The node's TrustedUserCAKeys is the session CA — present and self-contained.
		assertThat(sessionTrust).isNotEmpty();

		// It is a distinct kind: no host-CA or user-CA key is folded into it.
		assertThat(sessionTrust).doesNotContainAnyElementsOf(hostTrust).doesNotContainAnyElementsOf(userTrust);

		// There is no standing break-glass/incident CA — the trust set for that kind is
		// empty, so it can never be an entry in the node's TrustedUserCAKeys.
		assertThat(breakglassTrust).isEmpty();

		// Structurally: the three standing SSH CA kinds exist (alongside the internal
		// control-plane "mtls" CA, which the node never trusts); break-glass is not a
		// CA
		// kind at all — there is no standing incident CA to fold into node trust.
		List<String> kinds = db.sql("SELECT DISTINCT ca_kind FROM config.ca_config")
				.map(row -> row.get("ca_kind", String.class)).all().collectList().block();
		assertThat(kinds).contains("session", "user", "host").doesNotContain("breakglass");
	}
}
