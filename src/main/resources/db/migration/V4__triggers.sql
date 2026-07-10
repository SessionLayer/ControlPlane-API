-- V4 — Triggers: audit append-only + generation-counter monotonicity.
-- SessionLayer Control Plane. Enforces two invariants in the DATABASE, not by
-- application convention (operating doctrine §4.6 / §7).

-- ---------------------------------------------------------------------------
-- audit_event is APPEND-ONLY (Design §4.6, FR-AUD-9). Immutability is enforced
-- here so it does not depend on application discipline. A dedicated INSERT/SELECT
-- writer role is an additional S15/S16 deployment hardening layer on top of this.
--
--   * BEFORE UPDATE OR DELETE (row level): reject mutation/removal of any row.
--   * BEFORE TRUNCATE (statement level): reject wholesale wipe.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION runtime.audit_event_immutable()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'runtime.audit_event is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$;
COMMENT ON FUNCTION runtime.audit_event_immutable() IS 'Append-only guard for runtime.audit_event (Design §4.6).';

CREATE OR REPLACE TRIGGER audit_event_no_update_delete
    BEFORE UPDATE OR DELETE ON runtime.audit_event
    FOR EACH ROW EXECUTE FUNCTION runtime.audit_event_immutable();

CREATE OR REPLACE TRIGGER audit_event_no_truncate
    BEFORE TRUNCATE ON runtime.audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION runtime.audit_event_immutable();

-- ---------------------------------------------------------------------------
-- Generation counter is monotonic (Design §8.2). A renewal that would DECREASE
-- the generation counter is rejected at the DB layer — defense in depth beneath
-- the application's @Version optimistic-concurrency guard. A cloned credential
-- that forks the counter cannot regress the stored value via a stale write.
-- (Equality is allowed: an idempotent re-write of the same generation is benign.)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION runtime.enforce_generation_monotonic()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.generation < OLD.generation THEN
        RAISE EXCEPTION 'generation counter must not decrease (% -> %) for %.% id=%',
            OLD.generation, NEW.generation, TG_TABLE_SCHEMA, TG_TABLE_NAME, OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION runtime.enforce_generation_monotonic() IS 'Rejects a decreasing generation counter (Design §8.2).';

CREATE OR REPLACE TRIGGER agent_identity_generation_monotonic
    BEFORE UPDATE ON runtime.agent_identity
    FOR EACH ROW EXECUTE FUNCTION runtime.enforce_generation_monotonic();

CREATE OR REPLACE TRIGGER gateway_identity_generation_monotonic
    BEFORE UPDATE ON runtime.gateway_identity
    FOR EACH ROW EXECUTE FUNCTION runtime.enforce_generation_monotonic();

-- ---------------------------------------------------------------------------
-- Presence ownership nonce is monotonic (Design §10.2/§10.3, FR-HA-2/FR-HA-5).
-- The nonce is the anti-stale-ownership fencing token: routing fails closed on a
-- stale nonce, so a write that LOWERS it (a stale/duplicated Gateway re-claiming a
-- node it no longer owns) is a split-brain hazard. The @Version column guards a lost
-- update but not a stale-value write; this trigger closes that gap — the exact
-- defense already applied to the generation counter.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION runtime.enforce_presence_nonce_monotonic()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.nonce < OLD.nonce THEN
        RAISE EXCEPTION 'presence nonce must not decrease (% -> %) for node_id=%',
            OLD.nonce, NEW.nonce, OLD.node_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION runtime.enforce_presence_nonce_monotonic() IS 'Rejects a decreasing presence ownership nonce (Design §10.3).';

CREATE OR REPLACE TRIGGER presence_nonce_monotonic
    BEFORE UPDATE ON runtime.presence
    FOR EACH ROW EXECUTE FUNCTION runtime.enforce_presence_nonce_monotonic();

-- ---------------------------------------------------------------------------
-- recording_ref provenance is write-once (Design §15 "crown jewels", FR-AUD-3).
-- object_key / encryption_key_ref / hash_chain_head locate, decrypt and verify a
-- recording; silently rewriting them is evidence tampering. Once set (non-NULL) they
-- may not change (S9 sets hash_chain_head after creation, so a NULL->value transition
-- is allowed; value->different-value is not). Mutable operational fields (worm_mode,
-- size_bytes, version, updated_at) stay updatable.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION runtime.enforce_recording_ref_write_once()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.object_key IS DISTINCT FROM OLD.object_key
        OR NEW.encryption_key_ref IS DISTINCT FROM OLD.encryption_key_ref
        OR (OLD.hash_chain_head IS NOT NULL AND NEW.hash_chain_head IS DISTINCT FROM OLD.hash_chain_head) THEN
        RAISE EXCEPTION 'recording_ref provenance (session_id/object_key/encryption_key_ref/hash_chain_head) is write-once'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;
COMMENT ON FUNCTION runtime.enforce_recording_ref_write_once() IS 'Makes recording provenance columns write-once (Design §15 / FR-AUD-3).';

CREATE OR REPLACE TRIGGER recording_ref_write_once
    BEFORE UPDATE ON runtime.recording_ref
    FOR EACH ROW EXECUTE FUNCTION runtime.enforce_recording_ref_write_once();
