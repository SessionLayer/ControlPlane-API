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

CREATE TRIGGER audit_event_no_update_delete
    BEFORE UPDATE OR DELETE ON runtime.audit_event
    FOR EACH ROW EXECUTE FUNCTION runtime.audit_event_immutable();

CREATE TRIGGER audit_event_no_truncate
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

CREATE TRIGGER agent_identity_generation_monotonic
    BEFORE UPDATE ON runtime.agent_identity
    FOR EACH ROW EXECUTE FUNCTION runtime.enforce_generation_monotonic();

CREATE TRIGGER gateway_identity_generation_monotonic
    BEFORE UPDATE ON runtime.gateway_identity
    FOR EACH ROW EXECUTE FUNCTION runtime.enforce_generation_monotonic();
