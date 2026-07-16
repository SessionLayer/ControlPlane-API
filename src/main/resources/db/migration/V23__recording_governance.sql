-- V23 — Recording retention/governance delete + the recording:delete permission.
-- SessionLayer Control Plane, Session Eighteen. Forward-only, additive; V1-V22 unchanged.
--
-- Two concerns (Design §12.2/§12.3; FR-AUD-3/6, FR-PADM-1):
--   1. config.platform_role gains the recording:delete permission — the
--      specifically-privileged, audited custodian verb gating governance-mode
--      erasure (the GDPR escape hatch) and legal-hold custody. Extends the closed
--      vocabulary CHECK the same way V18/V20 did (drop + recreate; existing roles
--      stay a subset).
--   2. runtime.recording_ref gains retention/governance-delete lifecycle columns.
--      The provenance row is NEVER deleted (crown jewels, §15 / ON DELETE RESTRICT);
--      instead the encrypted OBJECT is deleted and the row is MARKED pruned — so the
--      audit trail that a recording existed (and was expired/erased, by whom) is
--      preserved while the personal data (the recorded bytes) is gone.

-- 1. ------------------------------------------------------------------------
ALTER TABLE config.platform_role DROP CONSTRAINT platform_role_permissions_check;
ALTER TABLE config.platform_role
    ADD CONSTRAINT platform_role_permissions_check
    CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll',
        'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export', 'recording:delete',
        'audit:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[]);

-- 2. ------------------------------------------------------------------------
-- Retention/governance-delete lifecycle. All nullable + mutable (NOT write-once — the
-- V8 trigger guards only session_id/object_key/encryption_key_ref/hash_chain_head/
-- content_digest, so these are freely settable by the pruner / governance-delete).
ALTER TABLE runtime.recording_ref
    ADD COLUMN pruned_at         timestamptz,                    -- when the encrypted object was deleted; metadata retained
    ADD COLUMN delete_mode       text CHECK (delete_mode IS NULL
                                 OR delete_mode IN ('retention', 'governance')),
    ADD COLUMN deleted_by        text,                           -- actor for a governance delete (NULL for automated retention)
    ADD COLUMN legal_hold_reason text;                           -- optional reason captured when a hold is placed

COMMENT ON COLUMN runtime.recording_ref.pruned_at IS 'FR-AUD-6: when the encrypted object was deleted (retention prune or governance delete). The metadata row is retained (crown-jewels provenance, §15).';
COMMENT ON COLUMN runtime.recording_ref.delete_mode IS 'FR-AUD-3/6: how the object was deleted — retention (automated, past retention_until) or governance (privileged, audited erasure).';
COMMENT ON COLUMN runtime.recording_ref.deleted_by IS 'FR-PADM-3: the recording:delete-privileged actor for a governance delete (NULL for automated retention prune).';
COMMENT ON COLUMN runtime.recording_ref.legal_hold_reason IS 'FR-AUD-6: optional reason captured when a legal hold is placed (blocks retention prune + governance delete).';

-- Refresh the prune helper to also skip already-pruned rows (idempotent re-prune).
-- Compliance-mode and legal-held recordings are still never returned.
-- Same return signature as V8 (so CREATE OR REPLACE is valid); the WHERE excludes
-- compliance, so every returned object is governance-mode-deletable.
CREATE OR REPLACE FUNCTION runtime.recording_prunable(cutoff timestamptz)
    RETURNS TABLE (id uuid, object_key text)
    LANGUAGE sql STABLE AS $$
    SELECT r.id, r.object_key
    FROM runtime.recording_ref r
    WHERE r.legal_hold = false
      AND r.worm_mode IS DISTINCT FROM 'compliance'
      AND r.retention_until IS NOT NULL
      AND r.retention_until <= cutoff
      AND r.pruned_at IS NULL;
$$;
COMMENT ON FUNCTION runtime.recording_prunable(timestamptz) IS 'FR-AUD-6: recordings eligible for retention pruning (governance + past retention_until + no legal hold + not already pruned). Compliance/legal-held never returned.';

-- Retained columns keep their grants (ALTER TABLE ADD COLUMN preserves them); the
-- CREATE OR REPLACE FUNCTION keeps its EXECUTE grants. No GRANT changes needed.
