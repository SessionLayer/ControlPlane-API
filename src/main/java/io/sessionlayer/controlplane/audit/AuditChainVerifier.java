package io.sessionlayer.controlplane.audit;

import io.sessionlayer.controlplane.data.runtime.AuditEvent;
import java.util.List;

/**
 * Recomputes and checks the {@code audit_event} hash chain (FR-AUD-3): a pure
 * function over the chained rows in {@code seq} order. It proves the two
 * tamper-evidence properties the WORM append-only table cannot prove by itself
 * — that no row's content was altered and that no row was removed or reordered
 * — so a compromised operator who somehow bypassed the append-only trigger
 * still leaves a detectable break (§15 "a compromised CP/admin can't alter a
 * recording/audit trail").
 *
 * <p>
 * For each row it checks (1) {@code prev_hash} equals the predecessor's
 * {@code record_hash} ({@link AuditRecordHash#GENESIS} for the first row) — a
 * removed/reordered row snaps this link — and (2) {@code record_hash} equals
 * {@code SHA-256(prev_hash ‖ canonical(event))} — a mutated field changes the
 * recomputed digest.
 */
public final class AuditChainVerifier {

	private AuditChainVerifier() {
	}

	/** The outcome: {@code valid}, or the first broken row with the reason. */
	public record Result(boolean valid, String failure) {

		static Result ok() {
			return new Result(true, null);
		}

		static Result broken(String failure) {
			return new Result(false, failure);
		}
	}

	/**
	 * Verify a chain presented in ascending {@code seq} order. Every row must carry
	 * a non-null {@code prev_hash}/{@code record_hash} (callers pass the chained
	 * subset).
	 */
	public static Result verify(List<AuditEvent> chainInSeqOrder) {
		String expectedPrev = AuditRecordHash.GENESIS;
		for (AuditEvent event : chainInSeqOrder) {
			if (event.recordHash() == null || event.prevHash() == null) {
				return Result.broken("unchained row in chain: " + event.id());
			}
			if (!expectedPrev.equals(event.prevHash())) {
				return Result.broken("prev_hash link broken at " + event.id());
			}
			if (!AuditRecordHash.recordHash(event.prevHash(), event).equals(event.recordHash())) {
				return Result.broken("record_hash mismatch at " + event.id());
			}
			expectedPrev = event.recordHash();
		}
		return Result.ok();
	}
}
