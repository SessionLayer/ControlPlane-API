package io.sessionlayer.controlplane.bootstrap;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * First-admin bootstrap configuration (Design §2A, FR-BOOT-2). If
 * {@code adminSubject} is set, that OIDC subject is provisioned as the initial
 * platform admin at startup; otherwise a printed-once bootstrap credential is
 * generated and must be claimed. Either way the bootstrap self-disables once a
 * platform admin exists.
 */
@ConfigurationProperties(prefix = "sessionlayer.bootstrap")
public class BootstrapProperties {

	/** A config-named OIDC subject to provision as the first platform admin. */
	private String adminSubject;

	/** The subject kind for {@code adminSubject}: {@code user} or {@code group}. */
	private String adminSubjectKind = "user";

	public String getAdminSubject() {
		return adminSubject;
	}

	public void setAdminSubject(String adminSubject) {
		this.adminSubject = adminSubject;
	}

	public String getAdminSubjectKind() {
		return adminSubjectKind;
	}

	public void setAdminSubjectKind(String adminSubjectKind) {
		this.adminSubjectKind = adminSubjectKind;
	}
}
