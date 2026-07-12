package io.sessionlayer.controlplane.recording;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Boundary normalization of the SFTP/SCP file-transfer audit metadata
 * (FR-AUD-1).
 */
class SftpAuditPolicyTest {

	@Test
	void allowlistedOperationSurvivesAndIsLowercased() {
		assertThat(SftpAuditPolicy.normalize(entry("WRITE", "up")).operation()).isEqualTo("write");
		assertThat(SftpAuditPolicy.normalize(entry("realpath", "up")).operation()).isEqualTo("realpath");
	}

	@Test
	void hostileMetadataIsNeutralized() {
		FileTransferAuditEntry hostile = new FileTransferAuditEntry("rm -rf /; DROP TABLE", "/" + "a".repeat(9000),
				"sideways", -5, "not-a-hash");
		FileTransferAuditEntry clean = SftpAuditPolicy.normalize(hostile);
		assertThat(clean.operation()).isEqualTo("unknown");
		assertThat(clean.direction()).isEqualTo("unknown");
		assertThat(clean.sha256()).isNull();
		assertThat(clean.path().length()).isLessThanOrEqualTo(4096);
		assertThat(clean.size()).isZero();
	}

	@Test
	void wellFormedShaAndDirectionAreKept() {
		String sha = "sha256:" + "b".repeat(64);
		FileTransferAuditEntry clean = SftpAuditPolicy
				.normalize(new FileTransferAuditEntry("read", "/etc/x", "download", 42, sha));
		assertThat(clean.direction()).isEqualTo("download");
		assertThat(clean.sha256()).isEqualTo(sha);
		assertThat(clean.size()).isEqualTo(42);
	}

	private static FileTransferAuditEntry entry(String operation, String direction) {
		return new FileTransferAuditEntry(operation, "/path", direction, 1, null);
	}
}
