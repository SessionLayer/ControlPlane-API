# F-legalhold-prune-toctou-1: Legal hold placed mid-prune-cycle was ignored — the held object was erased (WORM guardrail §11 bypass)

- Severity: medium
- Status: Verified-Fixed
- Area: security

`recording_prunable(:cutoff)` correctly excludes legal_hold/compliance at query time, but `pruneOne` re-read the row and only re-checked `pruned_at`, not `legal_hold`/compliance. A `setLegalHold(held=true)` after the snapshot but before the row was processed was missed, and the object was irreversibly deleted BEFORE the @Version save could fail — permanently erasing evidence under an active hold (spoliation), directly violating SESSION §11. Also caused an HA double-delete (F6) and possible mis-attribution (F7).

**Fix (Verified-Fixed, ddff505):** both delete paths now ATOMICALLY CLAIM the row before touching the object — `UPDATE runtime.recording_ref SET pruned_at=:now, delete_mode=…, [deleted_by=:actor,] version=version+1 WHERE id=:id AND pruned_at IS NULL AND legal_hold=false AND worm_mode IS DISTINCT FROM 'compliance' RETURNING object_key, worm_mode, session_id`. Only a claimed row's object is deleted; a racing hold either wins the row or fails the WHERE (0-row claim → governanceDelete 409). Eliminates the window + the double-delete + the mis-attribution. Residual (post-claim object-delete failure) tracked in F-retention-claim-delete-residual-1.
