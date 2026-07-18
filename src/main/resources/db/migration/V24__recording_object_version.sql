-- V24 — recording_ref.object_version_id: pin replay/export to the finalized
-- object-store version (F-recording-worm-version-1 / Design §15 crown jewels).
-- SessionLayer Control Plane.
--
-- S3 Object Lock protects an object VERSION, not the key from a NEW PUT: a later
-- PUT to the same key becomes the "current" version an unversioned GET returns. A
-- compromised CP (which holds the customer PUBLIC key and so can SEAL a forgery) or
-- a compromised Gateway could shadow a finalized recording with a re-sealed version
-- to the same key. Recording the version id the Gateway actually PUT — and pinning
-- replay/export to it — makes the finalized bytes the only ones served. The column
-- is WRITE-ONCE (like hash_chain_head / content_digest), so even a compromised app
-- credential (cp_runtime) cannot repoint it; a DB superuser rewriting it is the same
-- residual the deferred external Merkle anchor addresses (FR-AUD-10).

ALTER TABLE runtime.recording_ref
    ADD COLUMN object_version_id text;

COMMENT ON COLUMN runtime.recording_ref.object_version_id IS 'F-recording-worm-version-1 (§15): object-store version id of the finalized ciphertext object; replay/export pin it so a later shadow PUT to the same key is never served. Write-once once set (V24 trigger).';

-- Extend the write-once provenance guard to object_version_id (NULL->value once,
-- then frozen), alongside session_id/object_key/encryption_key_ref/hash_chain_head/
-- content_digest. CREATE OR REPLACE updates the function the existing
-- recording_ref_write_once trigger (V4) already calls.
CREATE OR REPLACE FUNCTION runtime.enforce_recording_ref_write_once()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.object_key IS DISTINCT FROM OLD.object_key
        OR NEW.encryption_key_ref IS DISTINCT FROM OLD.encryption_key_ref
        OR (OLD.hash_chain_head IS NOT NULL AND NEW.hash_chain_head IS DISTINCT FROM OLD.hash_chain_head)
        OR (OLD.content_digest IS NOT NULL AND NEW.content_digest IS DISTINCT FROM OLD.content_digest)
        OR (OLD.object_version_id IS NOT NULL AND NEW.object_version_id IS DISTINCT FROM OLD.object_version_id) THEN
        RAISE EXCEPTION 'recording_ref provenance (session_id/object_key/encryption_key_ref/hash_chain_head/content_digest/object_version_id) is write-once'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;
