-- V2 — CONFIG schema (Git-reconcilable entities). SessionLayer Control Plane.
--
-- Design §12A "Core data model" (CONFIG group) + §13 (config-vs-runtime boundary,
-- GitOps precedence) + FR-DATA-1. Every table here lives in the `config` schema and
-- carries an `origin` column so the S16 GitOps reconciler can disambiguate ownership
-- (git|api|ui|default) and revert Git-owned drift loudly. The reconciler touches
-- CONFIG only; RUNTIME (V3) is never reconciled.
--
-- Conventions (see docs/DATA-MODEL.md):
--   * PK = uuid, app-generated UUIDv7 (no DB extension needed).
--   * version bigint = the R2DBC @Version column (solves the is-new problem for a
--     client-assigned id; also optimistic-concurrency).
--   * Closed enums = text + CHECK (never native ENUM — expand/contract friendly).
--   * Selectors = jsonb (shape-validated); capability/permission sets = text[] with
--     a subset CHECK.
--   * created_at/updated_at = bookkeeping (auditing-managed); DEFAULT now() is a
--     belt-and-suspenders for raw inserts.
--
-- Forward-only: never edit this file after merge; change = a new versioned migration.

CREATE SCHEMA IF NOT EXISTS config;

-- ---------------------------------------------------------------------------
-- node_policy — desired labels, connector kind, declared host trust references.
-- ---------------------------------------------------------------------------
CREATE TABLE config.node_policy (
    id              uuid        PRIMARY KEY,
    name            text        NOT NULL UNIQUE,                 -- stable policy key for matching
    desired_labels  jsonb       NOT NULL DEFAULT '{}'
                                CHECK (jsonb_typeof(desired_labels) = 'object'),
    connector_kind  text        NOT NULL CHECK (connector_kind IN ('agent', 'agentless')),
    host_pin_ref    text        CHECK (host_pin_ref IS NULL OR host_pin_ref NOT LIKE '%PRIVATE KEY%'),
    host_ca_ref     text        CHECK (host_ca_ref IS NULL OR host_ca_ref NOT LIKE '%PRIVATE KEY%'),
    origin          text        NOT NULL DEFAULT 'default'
                                CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version         bigint      NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.node_policy IS 'Design §12A CONFIG: NodePolicy — desired node labels + connector + host trust refs.';

-- ---------------------------------------------------------------------------
-- dp_rule — data-plane grant (identity × node-label × source-IP -> principals,
-- ttl, capabilities, allow|deny). Design §6.1, FR-AUTHZ-1. Lock is NOT here.
-- ---------------------------------------------------------------------------
CREATE TABLE config.dp_rule (
    id                  uuid    PRIMARY KEY,
    name                text    NOT NULL UNIQUE,
    identity_selector   jsonb   NOT NULL CHECK (jsonb_typeof(identity_selector) = 'object'),
    node_label_selector jsonb   NOT NULL CHECK (jsonb_typeof(node_label_selector) = 'object'),
    source_ip_condition jsonb   CHECK (source_ip_condition IS NULL
                                       OR jsonb_typeof(source_ip_condition) = 'object'),
    principals          text[]  NOT NULL,
    ttl_seconds         integer NOT NULL CHECK (ttl_seconds > 0),
    capabilities        text[]  NOT NULL DEFAULT ARRAY['shell', 'exec']::text[]
                                CHECK (capabilities <@ ARRAY['shell', 'exec', 'sftp', 'scp',
                                    'port_forward_local', 'port_forward_remote',
                                    'agent_forward', 'x11']::text[]),
    effect              text    NOT NULL CHECK (effect IN ('allow', 'deny')),
    origin              text    NOT NULL DEFAULT 'default'
                                CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version             bigint  NOT NULL DEFAULT 0,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.dp_rule IS 'Design §6.1 / FR-AUTHZ-1: data-plane RBAC grant (typed policy-as-data). S5 evaluates.';

-- ---------------------------------------------------------------------------
-- platform_role — named set of granular platform permissions. FR-PADM-1.
-- ---------------------------------------------------------------------------
CREATE TABLE config.platform_role (
    id          uuid    PRIMARY KEY,
    name        text    NOT NULL UNIQUE,
    permissions text[]  NOT NULL
                        CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll',
                            'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
                            'request:approve', 'recording:replay', 'recording:export',
                            'audit:read', 'user:manage', 'settings:write']::text[]),
    description text,
    origin      text    NOT NULL DEFAULT 'default'
                        CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version     bigint  NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.platform_role IS 'FR-PADM-1: platform RBAC role = granular permission set.';

-- ---------------------------------------------------------------------------
-- role_binding — subject (user/group) -> platform_role, optionally scoped. FR-PADM-2.
-- config->config FK is allowed (same class).
-- ---------------------------------------------------------------------------
CREATE TABLE config.role_binding (
    id           uuid   PRIMARY KEY,
    role_id      uuid   NOT NULL REFERENCES config.platform_role (id) ON DELETE CASCADE,
    subject_kind text   NOT NULL CHECK (subject_kind IN ('user', 'group')),
    subject      text   NOT NULL,
    scope        jsonb  CHECK (scope IS NULL OR jsonb_typeof(scope) = 'object'),  -- node-label/user/time scope
    origin       text   NOT NULL DEFAULT 'default'
                        CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version      bigint NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (role_id, subject_kind, subject)
);
COMMENT ON TABLE config.role_binding IS 'FR-PADM-2: binds a subject to a platform_role; scope for recording:replay/export.';

-- ---------------------------------------------------------------------------
-- ca_config — per-CA backend + key REFERENCE (never private material). FR-CA-1/4.
-- ---------------------------------------------------------------------------
CREATE TABLE config.ca_config (
    id            uuid   PRIMARY KEY,
    name          text   NOT NULL UNIQUE,                        -- stable config name (a kind may have >1 row during rotation)
    ca_kind       text   NOT NULL CHECK (ca_kind IN ('user', 'session', 'host')),
    backend       text   NOT NULL CHECK (backend IN ('local', 'aws_kms', 'azure_keyvault', 'vault')),
    key_reference text   NOT NULL                                -- reference/handle only — NEVER private key material
                         CHECK (key_reference NOT LIKE '%PRIVATE KEY%' AND key_reference NOT LIKE '%BEGIN %'),
    algorithm     text   NOT NULL DEFAULT 'ecdsa-p256'
                         CHECK (algorithm IN ('ecdsa-p256', 'ecdsa-p384', 'ed25519', 'rsa-2048', 'rsa-4096')),
    -- CA rotation (FR-CA-7) requires the outgoing + incoming CA keys to be trusted
    -- simultaneously during the overlap window, so a CA kind may have multiple rows;
    -- exactly one is 'active' at a time (partial unique index in V5). S3 owns the
    -- rotation state machine (standby -> incoming -> active -> outgoing -> expired).
    rotation_state text NOT NULL DEFAULT 'active'
                         CHECK (rotation_state IN ('incoming', 'active', 'outgoing', 'expired')),
    origin        text   NOT NULL DEFAULT 'default'
                         CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version       bigint NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.ca_config IS 'FR-CA-1/4/7: per-CA (user|session|host) backend + key reference; multiple rows per kind support rotation overlap (one active). Default ECDSA P-256. Never stores private key material.';

-- ---------------------------------------------------------------------------
-- capability_def — the requestable-capability catalogue.
-- ---------------------------------------------------------------------------
CREATE TABLE config.capability_def (
    id          uuid   PRIMARY KEY,
    name        text   NOT NULL UNIQUE
                       CHECK (name IN ('shell', 'exec', 'sftp', 'scp', 'port_forward_local',
                           'port_forward_remote', 'agent_forward', 'x11')),
    description text,
    origin      text   NOT NULL DEFAULT 'default'
                       CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version     bigint NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.capability_def IS 'Design §12A CONFIG: requestable-capability catalogue.';

-- ---------------------------------------------------------------------------
-- jit_policy — what is JIT-requestable + approval-chain config (0-3 levels). FR-ACC-3.
-- ---------------------------------------------------------------------------
CREATE TABLE config.jit_policy (
    id              uuid    PRIMARY KEY,
    name            text    NOT NULL UNIQUE,
    target_selector jsonb   NOT NULL CHECK (jsonb_typeof(target_selector) = 'object'),
    capabilities    text[]  NOT NULL DEFAULT ARRAY[]::text[]
                            CHECK (capabilities <@ ARRAY['shell', 'exec', 'sftp', 'scp',
                                'port_forward_local', 'port_forward_remote',
                                'agent_forward', 'x11']::text[]),
    max_ttl_seconds integer NOT NULL CHECK (max_ttl_seconds > 0),
    -- approval_chain: ordered array of levels, each {kind: email|oidc_group, value}. 0-3 levels (FR-ACC-3).
    approval_chain  jsonb   NOT NULL DEFAULT '[]'
                            CHECK (jsonb_typeof(approval_chain) = 'array'
                                   AND jsonb_array_length(approval_chain) <= 3),
    origin          text    NOT NULL DEFAULT 'default'
                            CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version         bigint  NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.jit_policy IS 'FR-ACC-3: JIT-requestable targets + 0-3 level approval chain (email/OIDC-group).';

-- ---------------------------------------------------------------------------
-- breakglass_policy — break-glass config. FR-ACC-6.
-- ---------------------------------------------------------------------------
CREATE TABLE config.breakglass_policy (
    id                uuid    PRIMARY KEY,
    name              text    NOT NULL UNIQUE,
    recording_strict  boolean NOT NULL DEFAULT true,             -- session dies if recording fails
    alert_target      text    NOT NULL,                          -- high-priority alert destination (reference)
    review_required   boolean NOT NULL DEFAULT true,
    auth_path         text    NOT NULL DEFAULT 'fido2'
                              CHECK (auth_path IN ('fido2', 'offline_code')),  -- IdP-independent path
    origin            text    NOT NULL DEFAULT 'default'
                              CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version           bigint  NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.breakglass_policy IS 'FR-ACC-6: break-glass — recording-strict, alert, review, IdP-independent auth path.';

-- ---------------------------------------------------------------------------
-- service_account — machine-consumer DEFINITION (issued creds are runtime). FR-AUTH-12.
-- ---------------------------------------------------------------------------
CREATE TABLE config.service_account (
    id                uuid    PRIMARY KEY,
    name              text    NOT NULL UNIQUE,
    description       text,
    auth_method       text    NOT NULL DEFAULT 'private_key_jwt'
                              CHECK (auth_method IN ('private_key_jwt', 'mtls', 'client_secret')),
    -- public key / JWKS reference, never a secret. An issued client_secret (if that method
    -- is used) is a RUNTIME credential (a hash in a future service_account_credential table,
    -- see RESULT.md), never stored here. Content guard blocks a private key at rest.
    key_reference     text    CHECK (key_reference IS NULL OR key_reference NOT LIKE '%PRIVATE KEY%'),
    token_ttl_seconds integer CHECK (token_ttl_seconds IS NULL OR token_ttl_seconds > 0),
    origin            text    NOT NULL DEFAULT 'default'
                              CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version           bigint  NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.service_account IS 'FR-AUTH-12: machine-consumer definition. Issued credentials live in RUNTIME.';
