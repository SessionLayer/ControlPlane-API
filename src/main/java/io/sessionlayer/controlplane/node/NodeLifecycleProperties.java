package io.sessionlayer.controlplane.node;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for node lifecycle ({@code sessionlayer.node.*}, S16).
 */
@ConfigurationProperties(prefix = "sessionlayer.node")
public class NodeLifecycleProperties {

	/**
	 * Whether agentless enrollment requires operator approval. When on, a
	 * newly-registered node starts {@code pending} and is excluded from targeting
	 * until activated (FR-NODE-1). Default OFF — a pure-API provisioning flow
	 * (autoscaler / config-mgmt) activates immediately.
	 */
	private boolean enrollmentApprovalRequired = false;

	public boolean isEnrollmentApprovalRequired() {
		return enrollmentApprovalRequired;
	}

	public void setEnrollmentApprovalRequired(boolean enrollmentApprovalRequired) {
		this.enrollmentApprovalRequired = enrollmentApprovalRequired;
	}
}
