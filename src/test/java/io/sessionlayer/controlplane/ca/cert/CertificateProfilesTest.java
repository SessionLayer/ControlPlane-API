package io.sessionlayer.controlplane.ca.cert;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The capability → OpenSSH cert-extension mapping (FR-AUTHZ-6, default-deny) and
 * the A5-L2 agent-forwarding belt-and-suspenders.
 */
class CertificateProfilesTest {

	// F-agent-forward-cert-1 (A5-L2): FR-SESS-2 refuses agent forwarding at the
	// Gateway unconditionally, so a granted agent_forward capability MUST NOT put
	// permit-agent-forwarding into the inner cert — the node is never told to permit
	// it (defense-in-depth, not a single outer-leg control).
	@Test
	void grantedAgentForwardNeverYieldsPermitAgentForwarding() {
		assertThat(CertificateProfiles.extensionsFor(Set.of("shell", "agent_forward", "x11")))
				.contains("permit-pty", "permit-X11-forwarding").doesNotContain("permit-agent-forwarding");
	}

	@Test
	void defaultDenyGrantsNoExtensionForShellExecSftp() {
		// shell → permit-pty is the only flag extension; exec/sftp/scp are enforced at
		// the Gateway channel layer, not via a cert extension.
		assertThat(CertificateProfiles.extensionsFor(Set.of("exec", "sftp", "scp"))).isEmpty();
		assertThat(CertificateProfiles.extensionsFor(Set.of("shell"))).containsExactly("permit-pty");
	}
}
