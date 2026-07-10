-- V3 — RUNTIME schema (never reconciled). SessionLayer Control Plane.
--
-- Design §12A "Core data model" (RUNTIME group) + §13. These entities are the
-- live operational state: registrations, presence, issued identities, sessions,
-- recordings, locks, JIT/break-glass state, pins/OTPs, audit. The S16 GitOps
-- reconciler MUST NEVER touch anything in this schema (FR-API-3); there is
-- deliberately no `origin` column here.
--
-- Referential rules (docs/DATA-MODEL.md §6):
--   * runtime->runtime: real FKs (ON DELETE SET NULL where history must outlive the
--     referenced row; CASCADE only for the 1:1 recording_ref).
--   * runtime->config: NEVER a hard FK — decision *snapshots* (plain uuid + copied
--     principal/capabilities/access_model/policy_epoch) so history survives config GC.
--   * audit_event: zero FKs (immortal; correlation by id value).
--
-- Table order below respects FK dependencies.

CREATE SCHEMA IF NOT EXISTS runtime;

-- is_cidr(text) -> boolean: a total, safe CIDR-format validator used by the
-- source-CIDR CHECKs below. r2dbc-postgresql 1.1.1 has no cidr codec (see
-- docs/DATA-MODEL.md §9), so CIDR values are stored as text; a bare `(col)::cidr`
-- inside a CHECK would raise a *data exception* (SQLSTATE 22P02) on malformed input,
-- which surfaces as a grammar error to callers. Wrapping the parse in an exception
-- block turns malformed input into a clean CHECK (constraint) violation instead, so
-- application code sees a uniform integrity error for all bad-data rejections.
CREATE FUNCTION runtime.is_cidr(value text)
    RETURNS boolean
    LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
BEGIN
    RETURN value::cidr IS NOT NULL;
EXCEPTION
    WHEN others THEN
        RETURN false;
END;
$$;
COMMENT ON FUNCTION runtime.is_cidr(text) IS 'Total CIDR-format validator: malformed input -> false (clean CHECK violation), not a cast error.';

-- ---------------------------------------------------------------------------
-- node — live registration, resolved labels, health/status, owning gateway.
-- node.node_policy_name is a SNAPSHOT ref to config.node_policy (no FK: runtime->config).
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.node (
    id               uuid        PRIMARY KEY,
    name             text        NOT NULL UNIQUE,                -- stable node name / host key
    node_policy_name text,                                       -- snapshot ref to config.node_policy.name (NO FK)
    resolved_labels  jsonb       NOT NULL DEFAULT '{}'
                                 CHECK (jsonb_typeof(resolved_labels) = 'object'),
    connector_kind   text        NOT NULL CHECK (connector_kind IN ('agent', 'agentless')),
    status           text        NOT NULL DEFAULT 'pending'
                                 CHECK (status IN ('pending', 'active', 'quarantined', 'removed')),
    health           text        NOT NULL DEFAULT 'unknown'
                                 CHECK (health IN ('unknown', 'healthy', 'unhealthy', 'unreachable')),
    owning_gateway   text,                                       -- owning-gateway pointer (mirrors presence)
    address          text,                                       -- reachable address (agentless dial)
    version          bigint      NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.node IS 'Design §12A RUNTIME: live node registration; node_policy_name is a snapshot (no FK to config).';

-- ---------------------------------------------------------------------------
-- presence — who owns node X, at what address, with a monotonic nonce. §10.2 / FR-HA-2.
-- Keyed by node_id (1:1 with node; runtime->runtime FK).
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.presence (
    node_id        uuid        PRIMARY KEY REFERENCES runtime.node (id) ON DELETE CASCADE,
    owning_gateway text        NOT NULL,
    gateway_addr   text        NOT NULL,                         -- address carried in the signal (§10.2)
    nonce          bigint      NOT NULL,                         -- monotonic ownership nonce
    nonce_id       uuid        NOT NULL,
    last_seen      timestamptz NOT NULL,                         -- heartbeat (domain time)
    version        bigint      NOT NULL DEFAULT 0,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.presence IS 'Design §10.2 / FR-HA-2: node -> owning_gateway,addr,monotonic nonce. Queried before routing.';

-- ---------------------------------------------------------------------------
-- agent_identity — per-node mTLS identity ref + generation counter. Design §8, FR-JOIN-3/6.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.agent_identity (
    id                 uuid        PRIMARY KEY,
    node_id            uuid        NOT NULL REFERENCES runtime.node (id) ON DELETE CASCADE,
    mtls_identity_ref  text        NOT NULL,                     -- reference to the mTLS X.509 identity (never a key)
    fingerprint        text,                                     -- cert fingerprint
    generation         bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),  -- §8.2 generation counter
    join_method        text        NOT NULL CHECK (join_method IN ('token', 'oidc', 'mtls')),
    status             text        NOT NULL DEFAULT 'active'
                                   CHECK (status IN ('active', 'locked', 'revoked')),
    issued_at          timestamptz,
    not_after          timestamptz,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.agent_identity IS 'Design §8: agent mTLS identity + generation counter. One active per node (partial unique index, V5).';

-- ---------------------------------------------------------------------------
-- gateway_identity — Gateway CP-facing mTLS identity + generation. FR-BOOT-3.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.gateway_identity (
    id                uuid        PRIMARY KEY,
    name              text        NOT NULL UNIQUE,
    mtls_identity_ref text        NOT NULL,
    fingerprint       text,
    generation        bigint      NOT NULL DEFAULT 0 CHECK (generation >= 0),
    join_method       text        NOT NULL CHECK (join_method IN ('token', 'oidc', 'mtls')),
    status            text        NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active', 'locked', 'revoked')),
    issued_at         timestamptz,
    not_after         timestamptz,
    version           bigint      NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.gateway_identity IS 'FR-BOOT-3: Gateway is a first-class lockable principal; renewable mTLS identity + generation.';

-- ---------------------------------------------------------------------------
-- join_token — token HASH (never raw), scope, single-use, expiry, consumed_at.
-- Design §8.1 / FR-JOIN-2.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.join_token (
    id          uuid        PRIMARY KEY,
    token_hash  text        NOT NULL UNIQUE,                     -- hash of the token — the raw token is NEVER stored
    scope       jsonb       NOT NULL CHECK (jsonb_typeof(scope) = 'object'),  -- what the token may join as
    join_method text        NOT NULL CHECK (join_method IN ('token', 'oidc', 'mtls')),
    node_id     uuid        REFERENCES runtime.node (id) ON DELETE SET NULL,  -- optional pre-bind
    single_use  boolean     NOT NULL DEFAULT true,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    created_by  text,
    version     bigint      NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.join_token IS 'Design §8.1 / FR-JOIN-2: single-use join token. Stores token_hash only, never the raw token.';

-- ---------------------------------------------------------------------------
-- jit_request — FR-ACC-2 state machine, two clocks, approver-chain progress.
-- jit_policy_id is a SNAPSHOT ref to config.jit_policy (no FK). approval_chain is a
-- snapshot of the chain config at request time so later config edits don't rewrite history.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.jit_request (
    id                uuid        PRIMARY KEY,
    requester         text        NOT NULL,
    target_node_id    uuid        REFERENCES runtime.node (id) ON DELETE SET NULL,
    target_node_name  text,                                      -- snapshot (survives node delete)
    target_selector   jsonb       CHECK (target_selector IS NULL OR jsonb_typeof(target_selector) = 'object'),
    principal         text        NOT NULL,
    capabilities      text[]      NOT NULL DEFAULT ARRAY[]::text[]
                                  CHECK (capabilities <@ ARRAY['shell', 'exec', 'sftp', 'scp',
                                      'port_forward_local', 'port_forward_remote',
                                      'agent_forward', 'x11']::text[]),
    reason            text        NOT NULL,
    state             text        NOT NULL DEFAULT 'REQUESTED'
                                  CHECK (state IN ('REQUESTED', 'PENDING_APPROVAL', 'APPROVED',
                                      'DENIED', 'EXPIRED', 'ACTIVE', 'REVOKED')),
    jit_policy_id     uuid,                                      -- snapshot ref to config.jit_policy (NO FK)
    approval_chain    jsonb       NOT NULL DEFAULT '[]'          -- snapshot of the chain at request time
                                  CHECK (jsonb_typeof(approval_chain) = 'array'
                                         AND jsonb_array_length(approval_chain) <= 3),
    approvals         jsonb       NOT NULL DEFAULT '[]'          -- progress: who approved which level
                                  CHECK (jsonb_typeof(approvals) = 'array'),
    approval_deadline timestamptz,                               -- approval-window clock
    grant_expires_at  timestamptz,                               -- grant-TTL clock (bounds access-cred TTL)
    requested_at      timestamptz NOT NULL,
    decided_at        timestamptz,
    version           bigint      NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
-- Self-approval (approver != requester, FR-ACC-4) is a hard invariant enforced by S11
-- application logic over the `approvals` chain; it cannot be expressed as a row CHECK
-- over a jsonb array. Modelled here by keeping requester and approvals distinct.
COMMENT ON TABLE runtime.jit_request IS 'FR-ACC-2: JIT state machine + two clocks. jit_policy_id/approval_chain are snapshots.';

-- ---------------------------------------------------------------------------
-- ssh_session — the Design "session" entity (renamed; `session` is reserved, §7.1).
-- Carries the DECISION SNAPSHOT (Design §6): matched_rule_id (plain uuid, no FK),
-- resolved principal, capabilities, access_model, policy_epoch.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.ssh_session (
    id              uuid        PRIMARY KEY,
    identity        text        NOT NULL,                        -- human/subject identity (a value, not an FK)
    node_id         uuid        REFERENCES runtime.node (id) ON DELETE SET NULL,
    node_name       text,                                        -- snapshot (survives node delete)
    principal       text        NOT NULL,                        -- resolved linux principal (snapshot)
    gateway_id      uuid        REFERENCES runtime.gateway_identity (id) ON DELETE SET NULL,
    gateway_name    text,                                        -- snapshot
    access_model    text        NOT NULL CHECK (access_model IN ('standing', 'jit', 'breakglass')),
    capabilities    text[]      NOT NULL DEFAULT ARRAY[]::text[]
                                CHECK (capabilities <@ ARRAY['shell', 'exec', 'sftp', 'scp',
                                    'port_forward_local', 'port_forward_remote',
                                    'agent_forward', 'x11']::text[]),
    matched_rule_id uuid,                                        -- SNAPSHOT ref to config.dp_rule (NO FK)
    jit_request_id  uuid        REFERENCES runtime.jit_request (id) ON DELETE SET NULL,
    policy_epoch    bigint,                                      -- snapshot of the policy epoch at decision time
    started_at      timestamptz NOT NULL,
    ended_at        timestamptz,
    version         bigint      NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.ssh_session IS 'Design §12A "session" (renamed ssh_session, §7.1). Holds the decision snapshot (§6).';

-- ---------------------------------------------------------------------------
-- recording_ref — 1:1 with ssh_session (UNIQUE session_id + FK). FR-DATA-2 / FR-AUD-3.
-- encryption_key_ref is a REFERENCE (customer-held key), never key material.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.recording_ref (
    id                 uuid        PRIMARY KEY,
    session_id         uuid        NOT NULL UNIQUE
                                   REFERENCES runtime.ssh_session (id) ON DELETE CASCADE,  -- 1:1
    object_key         text        NOT NULL,                     -- WORM object-store key
    encryption_key_ref text        NOT NULL,                     -- customer-held key REFERENCE (never key material)
    hash_chain_head    text,                                     -- recording hash-chain head (S9 fills)
    worm_mode          text        CHECK (worm_mode IS NULL OR worm_mode IN ('compliance', 'governance')),
    size_bytes         bigint      CHECK (size_bytes IS NULL OR size_bytes >= 0),
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.recording_ref IS 'FR-DATA-2: 1:1 with ssh_session (UNIQUE session_id). encryption_key_ref is a reference only.';

-- ---------------------------------------------------------------------------
-- access_lock — the Design "lock" entity (renamed; reserved word, §7.1). API-ONLY.
-- No `origin` column: runtime, never reconciled. The reconciler MUST reject a
-- committed Lock kind (FR-API-3). Lock = top-tier un-overridable deny (Design §6.1/§8.4).
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.access_lock (
    id              uuid        PRIMARY KEY,
    target_selector jsonb       NOT NULL CHECK (jsonb_typeof(target_selector) = 'object'),  -- identity/role/login/node/...
    mode            text        NOT NULL CHECK (mode IN ('strict', 'best_effort')),
    ttl_seconds     integer     CHECK (ttl_seconds IS NULL OR ttl_seconds > 0),
    expires_at      timestamptz,
    reason          text        NOT NULL,
    created_by      text        NOT NULL,
    version         bigint      NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.access_lock IS 'Design §12A "lock" (renamed access_lock, §7.1). API-ONLY runtime resource (FR-API-3); never reconciled.';

-- ---------------------------------------------------------------------------
-- breakglass_activation — principal, reason, alert ref, review status. FR-ACC-6.
-- breakglass_policy_id is a SNAPSHOT ref (no FK).
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.breakglass_activation (
    id                   uuid        PRIMARY KEY,
    principal            text        NOT NULL,
    reason               text        NOT NULL,
    alert_ref            text,                                   -- reference to the fired alert
    breakglass_policy_id uuid,                                   -- snapshot ref to config.breakglass_policy (NO FK)
    review_status        text        NOT NULL DEFAULT 'pending'
                                     CHECK (review_status IN ('pending', 'reviewed')),
    reviewer             text,
    activated_at         timestamptz NOT NULL,
    reviewed_at          timestamptz,
    version              bigint      NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.breakglass_activation IS 'FR-ACC-6: break-glass activation with mandatory post-hoc review.';

-- ---------------------------------------------------------------------------
-- pin — pubkey fingerprint pin. Design §5.5. source_cidr = text + ::cidr CHECK (§9 driver note).
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.pin (
    id          uuid        PRIMARY KEY,
    fingerprint text        NOT NULL,                            -- pinned pubkey fingerprint
    identity    text        NOT NULL,
    source_cidr text        CHECK (source_cidr IS NULL OR runtime.is_cidr(source_cidr)),
    principals  text[]      NOT NULL,                            -- allowed linux principals
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    version     bigint      NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (fingerprint, identity)
);
COMMENT ON TABLE runtime.pin IS 'Design §5.5: authN-shortcut pin {fp, identity, source-cidr, principals, expiry}. source_cidr validated by ::cidr cast.';

-- ---------------------------------------------------------------------------
-- otp — OTP HASH (never raw), identity, allowed principals, source-cidr, expiry, used.
-- Design §5.4 / FR-AUTH-9. The atomic mark-used column (`used`) lives here.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.otp (
    id                 uuid        PRIMARY KEY,
    otp_hash           text        NOT NULL UNIQUE,              -- hash — the raw OTP is NEVER stored
    identity           text        NOT NULL,
    allowed_principals text[]      NOT NULL,
    source_cidr        text        CHECK (source_cidr IS NULL OR runtime.is_cidr(source_cidr)),
    expires_at         timestamptz NOT NULL,
    used               boolean     NOT NULL DEFAULT false,       -- atomic mark-used (FR-AUTH-9)
    used_at            timestamptz,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.otp IS 'Design §5.4 / FR-AUTH-9: single-use OTP. Stores otp_hash only, never the raw OTP.';

-- ---------------------------------------------------------------------------
-- audit_event — one correlated stream for SSH + web/admin trails. Design §12.2 / FR-AUD-9.
-- APPEND-ONLY (V4 trigger). ZERO FKs (immortal; correlation by id value). Hash-chain
-- columns (prev_hash/record_hash) reserved for S9.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.audit_event (
    id             uuid        PRIMARY KEY,                      -- UUIDv7 (time-ordered)
    occurred_at    timestamptz NOT NULL,                        -- semantic event time (UTC, FR-BOOT-4)
    actor          text        NOT NULL,                        -- who (identity)
    subject        text,                                        -- what/whom
    action         text        NOT NULL,
    outcome        text        NOT NULL CHECK (outcome IN ('success', 'failure', 'denied', 'error')),
    correlation_id uuid,                                         -- FR-AUD-9 join key (value, no FK)
    session_id     uuid,                                         -- soft ref (value, no FK)
    node_id        uuid,                                         -- soft ref (value, no FK)
    source_ip      text,                                         -- FR-AUD-8 search dim (cast ::inet at query)
    access_model   text        CHECK (access_model IS NULL
                                      OR access_model IN ('standing', 'jit', 'breakglass')),
    capabilities   text[]      CHECK (capabilities IS NULL OR capabilities <@ ARRAY['shell', 'exec',
                                   'sftp', 'scp', 'port_forward_local', 'port_forward_remote',
                                   'agent_forward', 'x11']::text[]),
    detail         jsonb       CHECK (detail IS NULL OR jsonb_typeof(detail) = 'object'),  -- decision detail
    prev_hash      text,                                        -- hash chain (S9 fills)
    record_hash    text,                                        -- hash chain (S9 fills)
    version        bigint      NOT NULL DEFAULT 0,              -- @Version (insert-only; never updated)
    created_at     timestamptz NOT NULL DEFAULT now()           -- bookkeeping insert time
);
COMMENT ON TABLE runtime.audit_event IS 'Design §12.2 / FR-AUD-9: single correlated audit stream. Append-only (V4 trigger); zero FKs; hash-chain cols reserved for S9.';
