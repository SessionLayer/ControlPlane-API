package io.sessionlayer.controlplane.recording;

import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Normalizes and bounds the per-operation SFTP/SCP file-transfer audit the
 * Gateway reports at {@code FinalizeRecording} (FR-AUD-1). The Gateway is a
 * trusted Tier-0 component, but the audit stream is evidence — so the CP still
 * validates this metadata at the boundary: the {@code operation} is allowlisted
 * (unknown → {@code "unknown"}, so a crafted value can't forge an arbitrary
 * {@code action}), {@code direction} is constrained, {@code sha256} is dropped
 * unless well-formed, and {@code path} is length-bounded. The batch size is
 * capped so a single finalize can't append an unbounded number of audit rows.
 */
public final class SftpAuditPolicy {

	/** Max file-transfer operations accepted in one FinalizeRecording. */
	public static final int MAX_BATCH = 4096;

	private static final int MAX_PATH = 4096;
	private static final Pattern SHA256 = Pattern.compile("^sha256:[0-9a-f]{64}$");
	private static final Set<String> OPERATIONS = Set.of("open", "read", "write", "close", "rename", "remove", "mkdir",
			"rmdir", "setstat", "fsetstat", "realpath", "stat", "lstat", "readdir", "symlink", "put", "get");

	private SftpAuditPolicy() {
	}

	public static FileTransferAuditEntry normalize(FileTransferAuditEntry entry) {
		String operation = entry.operation() == null ? "" : entry.operation().trim().toLowerCase(Locale.ROOT);
		operation = OPERATIONS.contains(operation) ? operation : "unknown";
		String direction = "upload".equals(entry.direction()) || "download".equals(entry.direction())
				? entry.direction()
				: "unknown";
		String path = entry.path() == null ? "" : entry.path();
		if (path.length() > MAX_PATH) {
			path = path.substring(0, MAX_PATH);
		}
		long size = Math.max(0, entry.size());
		String sha256 = entry.sha256() != null && SHA256.matcher(entry.sha256().trim()).matches()
				? entry.sha256().trim()
				: null;
		return new FileTransferAuditEntry(operation, path, direction, size, sha256);
	}
}
