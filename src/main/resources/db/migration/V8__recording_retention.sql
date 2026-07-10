-- V8 — recording_ref retention + status/digest. SessionLayer Control Plane.
--
-- Closes F-model-deferrals-1 / F-DM-10/11 and the recording half of FR-AUD-3/6:
--   * retention_until + legal_hold — a recording is prunable only once retention_until
--     has passed AND no legal hold is set AND it is not compliance-WORM (which is truly
--     un-deletable). recording_ref is 1:1 with a session and not partitioned, so its
--     prune is row-based and recording-aware (docs/DATA-MODEL.md §6).
--   * worm_mode default from operator_settings.default_worm_mode is applied by the
--     writing session (S9); the column keeps its CHECK.
--   * status/format/content_digest — finalized-vs-truncated lifecycle + integrity
--     digest (NFR-6). content_digest is write-once once set (extends the V4 trigger).

ALTER TABLE runtime.recording_ref
    ADD COLUMN retention_until timestamptz,
    ADD COLUMN legal_hold      boolean     NOT NULL DEFAULT false,
    ADD COLUMN status          text        NOT NULL DEFAULT 'recording'
                               CHECK (status IN ('recording', 'finalized', 'truncated', 'failed')),
    ADD COLUMN format          text        NOT NULL DEFAULT 'asciicast-v2'
                               CHECK (format IN ('asciicast-v2')),
    ADD COLUMN content_digest  text        CHECK (content_digest IS NULL
                               OR content_digest ~ '^sha256:[0-9a-f]{64}$');   -- streaming SHA-256 (FR-AUD-1)

COMMENT ON COLUMN runtime.recording_ref.retention_until IS 'FR-AUD-6: earliest time this recording may be pruned (governance mode only; compliance is never prunable; legal_hold overrides).';
COMMENT ON COLUMN runtime.recording_ref.legal_hold IS 'FR-AUD-6: when true the recording is exempt from retention pruning regardless of retention_until.';
COMMENT ON COLUMN runtime.recording_ref.status IS 'NFR-6: recording lifecycle — recording -> finalized|truncated|failed.';
COMMENT ON COLUMN runtime.recording_ref.content_digest IS 'NFR-6 integrity digest (sha256:<hex>); write-once once set (V8 trigger).';

-- Extend the write-once provenance guard (V4) to cover content_digest: NULL -> value is
-- allowed (set at finalize), value -> different value is rejected (evidence tampering).
-- CREATE OR REPLACE keeps the existing trigger binding.
CREATE OR REPLACE FUNCTION runtime.enforce_recording_ref_write_once()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.object_key IS DISTINCT FROM OLD.object_key
        OR NEW.encryption_key_ref IS DISTINCT FROM OLD.encryption_key_ref
        OR (OLD.hash_chain_head IS NOT NULL AND NEW.hash_chain_head IS DISTINCT FROM OLD.hash_chain_head)
        OR (OLD.content_digest IS NOT NULL AND NEW.content_digest IS DISTINCT FROM OLD.content_digest) THEN
        RAISE EXCEPTION 'recording_ref provenance (session_id/object_key/encryption_key_ref/hash_chain_head/content_digest) is write-once'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- Prune helper: recordings eligible for retention pruning (governance mode, past
-- retention_until, no legal hold). Compliance-mode and legal-held recordings are never
-- returned. A recording-aware pruner uses this to select object keys to expire.
CREATE OR REPLACE FUNCTION runtime.recording_prunable(cutoff timestamptz)
    RETURNS TABLE (id uuid, object_key text)
    LANGUAGE sql STABLE AS $$
    SELECT r.id, r.object_key
    FROM runtime.recording_ref r
    WHERE r.legal_hold = false
      AND r.worm_mode IS DISTINCT FROM 'compliance'
      AND r.retention_until IS NOT NULL
      AND r.retention_until <= cutoff;
$$;
COMMENT ON FUNCTION runtime.recording_prunable(timestamptz) IS 'FR-AUD-6: recordings eligible for retention pruning (governance + past retention_until + no legal hold). Compliance/legal-held never returned.';

CREATE INDEX idx_recording_retention ON runtime.recording_ref (retention_until)
    WHERE legal_hold = false;
