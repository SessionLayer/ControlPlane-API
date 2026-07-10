-- V10 — model-gap CONFIG tables + status-transition reason/actor columns.
-- SessionLayer Control Plane. Closes F-model-deferrals-1 items F-DM-5/8/15. Schema
-- only; the owning logic is a later session (S5 epoch, S7 limits, lifecycle actors).

-- ---------------------------------------------------------------------------
-- policy_epoch (F-DM-5, → S5) — the authoritative source of the policy epoch that
-- ssh_session / audit_event snapshot. Singleton counter; S5 bumps it on any config
-- change (under the @Version optimistic lock) so decisions stamp a monotonic epoch.
-- ---------------------------------------------------------------------------
CREATE TABLE config.policy_epoch (
    id         uuid        PRIMARY KEY,
    singleton  boolean     NOT NULL DEFAULT true UNIQUE CHECK (singleton = true),
    epoch      bigint      NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    version    bigint      NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.policy_epoch IS 'F-DM-5: authoritative monotonic policy epoch (singleton). S5 bumps it on config change; decisions snapshot it into ssh_session/audit_event.';

-- Monotonic guard: the epoch may never decrease (mirrors the generation/nonce guards).
CREATE OR REPLACE FUNCTION config.enforce_policy_epoch_monotonic()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.epoch < OLD.epoch THEN
        RAISE EXCEPTION 'policy epoch must not decrease (% -> %)', OLD.epoch, NEW.epoch
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER policy_epoch_monotonic
    BEFORE UPDATE ON config.policy_epoch
    FOR EACH ROW EXECUTE FUNCTION config.enforce_policy_epoch_monotonic();

-- ---------------------------------------------------------------------------
-- session_limit_policy (F-DM-8, FR-SESS-3, → S7) — per-identity session-limit
-- overrides (operator_settings holds the cluster defaults). Enforcement is S7.
-- ---------------------------------------------------------------------------
CREATE TABLE config.session_limit_policy (
    id                     uuid    PRIMARY KEY,
    name                   text    NOT NULL UNIQUE,
    identity_selector      jsonb   NOT NULL CHECK (jsonb_typeof(identity_selector) = 'object'),
    max_concurrent_sessions integer CHECK (max_concurrent_sessions IS NULL OR max_concurrent_sessions > 0),
    max_session_seconds    integer  CHECK (max_session_seconds IS NULL OR max_session_seconds > 0),
    idle_timeout_seconds   integer  CHECK (idle_timeout_seconds IS NULL OR idle_timeout_seconds > 0),
    origin                 text     NOT NULL DEFAULT 'default'
                                    CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version                bigint   NOT NULL DEFAULT 0,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.session_limit_policy IS 'F-DM-8 / FR-SESS-3: per-identity session-limit overrides (max concurrent/duration/idle). Cluster defaults live in operator_settings. Enforcement S7.';

-- ---------------------------------------------------------------------------
-- Status-transition reason/actor columns (F-DM-15) where status enums exist, so a
-- quarantine/revoke/lock is self-describing without stitching from audit_event.
-- ---------------------------------------------------------------------------
ALTER TABLE runtime.node
    ADD COLUMN status_reason     text,
    ADD COLUMN status_changed_by text,
    ADD COLUMN status_changed_at timestamptz;

ALTER TABLE runtime.agent_identity
    ADD COLUMN status_reason     text,
    ADD COLUMN status_changed_by text,
    ADD COLUMN status_changed_at timestamptz;

ALTER TABLE runtime.gateway_identity
    ADD COLUMN status_reason     text,
    ADD COLUMN status_changed_by text,
    ADD COLUMN status_changed_at timestamptz;

-- jit_request already has decided_at; add the actor + a distinct decision reason
-- (the existing `reason` is the requester's justification, FR-ACC-2).
ALTER TABLE runtime.jit_request
    ADD COLUMN decided_by      text,
    ADD COLUMN decision_reason text;

COMMENT ON COLUMN runtime.node.status_reason IS 'F-DM-15: why the node reached its current status (quarantine/remove reason).';
COMMENT ON COLUMN runtime.agent_identity.status_reason IS 'F-DM-15: why the identity reached its status (lock/revoke reason, e.g. generation mismatch).';
COMMENT ON COLUMN runtime.jit_request.decided_by IS 'F-DM-15: the approver/denier actor (distinct from the requester in `reason`).';
