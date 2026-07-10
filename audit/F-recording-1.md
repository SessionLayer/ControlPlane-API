# F-recording-1: recording metadata was CASCADE-erasable and freely mutable
- Severity: medium
- Status: Verified-Fixed
- Area: recording

## Summary
`recording_ref.session_id` was `ON DELETE CASCADE` and `object_key`/`encryption_key_ref`/`hash_chain_head`
were plain updatable columns (red-team M2, reliability M2). A single `DELETE FROM ssh_session` cascade-erased
the recording's object key, customer encryption-key reference, and hash-chain head; and those columns could be
silently rewritten.

## Impact
The WORM object bytes survive, but losing the encryption-key reference + hash-chain head renders a recording
unlocatable, undecryptable, and unverifiable — effective evidence destruction with no audit obstacle,
contradicting §15 "crown jewels / a compromised admin can't alter a recording" and FR-AUD-3.

## Remediation
- FK changed to **`ON DELETE RESTRICT`** — a session prune cannot cascade-erase recording provenance; a
  retention pruner must be recording-aware (documented, DATA-MODEL §6).
- **`recording_ref` provenance is write-once**: a `BEFORE UPDATE` trigger
  (`runtime.enforce_recording_ref_write_once()`) rejects changes to `session_id`/`object_key`/
  `encryption_key_ref` and to `hash_chain_head` once set (S9 sets it once, NULL→value allowed). Operational
  fields (`worm_mode`, `size_bytes`) stay mutable.

## Evidence
- `V3__runtime_schema.sql` (`recording_ref` FK RESTRICT); `V4__triggers.sql` (write-once trigger).
- `ConstraintsIT.recordingProvenanceIsWriteOnce`, `ConstraintsIT.sessionDeleteBlockedWhileRecordingExists`.
</content>
