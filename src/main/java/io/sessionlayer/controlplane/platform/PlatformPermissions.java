package io.sessionlayer.controlplane.platform;

import java.util.Set;

/**
 * The platform-RBAC permission vocabulary (FR-PADM-1) — the same closed set the
 * {@code platform_role.permissions} column CHECK-constrains. {@link #SCOPABLE}
 * are the permissions a {@code role_binding} may scope by node-label/user/time
 * (FR-PADM-2): {@code recording:replay} and {@code recording:export}.
 */
public final class PlatformPermissions {

	public static final String RBAC_READ = "rbac:read";
	public static final String RBAC_WRITE = "rbac:write";
	public static final String NODE_ENROLL = "node:enroll";
	public static final String NODE_QUARANTINE = "node:quarantine";
	public static final String NODE_REMOVE = "node:remove";
	public static final String CA_MANAGE = "ca:manage";
	public static final String CA_ROTATE = "ca:rotate";
	public static final String REQUEST_APPROVE = "request:approve";
	public static final String RECORDING_REPLAY = "recording:replay";
	public static final String RECORDING_EXPORT = "recording:export";
	/**
	 * Governance-mode erasure + legal-hold custody (FR-AUD-3/6): destructive,
	 * specifically-privileged.
	 */
	public static final String RECORDING_DELETE = "recording:delete";
	public static final String AUDIT_READ = "audit:read";
	public static final String USER_MANAGE = "user:manage";
	public static final String SETTINGS_WRITE = "settings:write";
	public static final String LOCK_READ = "lock:read";
	public static final String LOCK_WRITE = "lock:write";
	public static final String BREAKGLASS_MANAGE = "breakglass:manage";

	public static final Set<String> ALL = Set.of(RBAC_READ, RBAC_WRITE, NODE_ENROLL, NODE_QUARANTINE, NODE_REMOVE,
			CA_MANAGE, CA_ROTATE, REQUEST_APPROVE, RECORDING_REPLAY, RECORDING_EXPORT, RECORDING_DELETE, AUDIT_READ,
			USER_MANAGE, SETTINGS_WRITE, LOCK_READ, LOCK_WRITE, BREAKGLASS_MANAGE);

	public static final Set<String> SCOPABLE = Set.of(RECORDING_REPLAY, RECORDING_EXPORT);

	private PlatformPermissions() {
	}
}
