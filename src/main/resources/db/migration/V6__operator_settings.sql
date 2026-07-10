-- V6 — operator_settings (config). SessionLayer Control Plane, Session Three.
--
-- Closes F-model-deferrals-1 / F-DM-9: `settings:write` (FR-PADM-1) guarded a
-- resource that did not exist. This is the singleton cluster-configuration entity
-- that cold start (Design §2A / §5.5, FR-BOOT-1) reads to provision the three CAs,
-- and that later sessions read for retention/WORM/OTP/session-limit defaults and
-- the FR-BOOT-2 first-admin bootstrap self-disable flag.
--
-- Placement: CONFIG schema. These are operator-owned knobs (settings:write, a
-- CONFIG permission) and carry an `origin`. Two fields are runtime-managed and the
-- reconciler MUST NOT revert them (like access_lock is API-only): `bootstrap_*`
-- (set once when the first admin is provisioned, FR-BOOT-2) — documented in
-- docs/DATA-MODEL.md. Cold start writes this row at first boot.
--
-- Singleton: enforced by a `singleton boolean UNIQUE CHECK (singleton)` so at most
-- one row can ever exist (any second insert collides on the unique true value).

CREATE TABLE config.operator_settings (
    id                          uuid        PRIMARY KEY,
    -- one-row guard: only value 'true' is allowed and it is UNIQUE -> at most one row
    singleton                   boolean     NOT NULL DEFAULT true UNIQUE
                                            CHECK (singleton = true),

    -- Local-CA KEK is a REFERENCE only (env var name / KMS handle), never the KEK
    -- bytes; the actual key-encryption key is sourced from the environment at
    -- runtime (Design §14, FR-CA-8). Content guard blocks a key pasted here.
    kek_reference               text        CHECK (kek_reference IS NULL
                                            OR (kek_reference NOT LIKE '%PRIVATE KEY%'
                                                AND kek_reference NOT LIKE '%BEGIN %')),

    -- Default CA backend used by cold start when provisioning a kind with no row yet.
    default_ca_backend          text        NOT NULL DEFAULT 'local'
                                            CHECK (default_ca_backend IN ('local', 'aws_kms', 'azure_keyvault', 'vault')),

    -- Retention window for the audit_event range partitions (FR-AUD-6). Default is
    -- 365 days (>= 12 months). audit_prune_before(now() - retention) drops partitions
    -- entirely older than this.
    audit_retention_days        integer     NOT NULL DEFAULT 365 CHECK (audit_retention_days > 0),

    -- WORM default for new recordings (FR-AUD-3/6). Governance is deletable by a
    -- privileged audited role (GDPR escape hatch); compliance is truly un-deletable.
    default_worm_mode           text        NOT NULL DEFAULT 'governance'
                                            CHECK (default_worm_mode IN ('compliance', 'governance')),

    -- OTP TTL default (FR-AUTH-9: 60-300 s).
    otp_ttl_seconds             integer     NOT NULL DEFAULT 120
                                            CHECK (otp_ttl_seconds BETWEEN 60 AND 300),

    -- Per-session default limits (FR-SESS-3). Per-identity overrides live in
    -- config.session_limit_policy (V10); the enforcement semaphore is S7.
    default_max_session_seconds integer     CHECK (default_max_session_seconds IS NULL OR default_max_session_seconds > 0),
    default_idle_timeout_seconds integer    CHECK (default_idle_timeout_seconds IS NULL OR default_idle_timeout_seconds > 0),
    default_max_concurrent_sessions integer CHECK (default_max_concurrent_sessions IS NULL OR default_max_concurrent_sessions > 0),

    -- FR-BOOT-2 first-admin bootstrap (data only; the bootstrap FLOW is S6).
    -- subject = a config-named OIDC subject, OR a printed-once credential whose HASH
    -- (never the raw value) is stored here. `bootstrap_completed` is the self-disable
    -- flag: once a platform admin exists the bootstrap path turns off. RUNTIME-managed
    -- (the reconciler must not revert these two fields).
    bootstrap_admin_subject     text,
    bootstrap_credential_hash   text        CHECK (bootstrap_credential_hash IS NULL
                                            OR bootstrap_credential_hash NOT LIKE '%PRIVATE KEY%'),
    bootstrap_completed         boolean     NOT NULL DEFAULT false,
    bootstrap_completed_at      timestamptz,

    origin                      text        NOT NULL DEFAULT 'default'
                                            CHECK (origin IN ('git', 'api', 'ui', 'default')),
    version                     bigint      NOT NULL DEFAULT 0,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE config.operator_settings IS 'F-DM-9: singleton cluster settings (KEK ref, default CA backend, retention/WORM/OTP/session-limit defaults, FR-BOOT-2 bootstrap self-disable). Cold start reads/writes this. bootstrap_* fields are runtime-managed (reconciler must not revert).';
