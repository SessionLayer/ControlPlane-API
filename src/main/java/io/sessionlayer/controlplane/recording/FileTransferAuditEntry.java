package io.sessionlayer.controlplane.recording;

/**
 * One decoded SFTP/SCP file-transfer operation the Gateway reports at
 * {@code FinalizeRecording} (FR-AUD-1). METADATA ONLY — path, direction, size,
 * and the streaming SHA-256 of the transferred content; the file content itself
 * is never captured. Each entry is correlated into the {@code audit_event}
 * stream (FR-AUD-9).
 */
public record FileTransferAuditEntry(String operation, String path, String direction, long size, String sha256) {
}
