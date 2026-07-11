package io.sessionlayer.controlplane.authz;

import java.util.Set;

/**
 * The SSH capability vocabulary (FR-AUTHZ-6 / D14) and the default-deny
 * defaults. A grant that names no capabilities is read as the baseline
 * {@link #DEFAULT} ({@code shell}+{@code exec}); {@code agent_forward} is never
 * a default and must be granted explicitly (agent-forwarding default-deny).
 */
public final class Capabilities {

	public static final String SHELL = "shell";
	public static final String EXEC = "exec";
	public static final String SFTP = "sftp";
	public static final String SCP = "scp";
	public static final String PORT_FORWARD_LOCAL = "port_forward_local";
	public static final String PORT_FORWARD_REMOTE = "port_forward_remote";
	public static final String AGENT_FORWARD = "agent_forward";
	public static final String X11 = "x11";

	public static final Set<String> ALL = Set.of(SHELL, EXEC, SFTP, SCP, PORT_FORWARD_LOCAL, PORT_FORWARD_REMOTE,
			AGENT_FORWARD, X11);

	/** The default capability set for a grant that names none (§6.1). */
	public static final Set<String> DEFAULT = Set.of(SHELL, EXEC);

	private Capabilities() {
	}

	/** The capabilities a grant contributes: its explicit set, or the default. */
	public static Set<String> effective(Set<String> granted) {
		return (granted == null || granted.isEmpty()) ? DEFAULT : Set.copyOf(granted);
	}
}
