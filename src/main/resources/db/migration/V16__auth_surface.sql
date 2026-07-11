-- V16 — authentication surface (RUNTIME). SessionLayer Control Plane, Session Six.
-- Forward-only; V2–V15 unchanged. Adds the runtime state the OIDC relying party,
-- device flow, rate limiter and machine-identity paths need. No config table is
-- added: the OIDC provider (issuer/client/alg allow-list/skew) is application
-- config (Open values, RESULT §7), and the first-admin bootstrap reuses the
-- existing config.operator_settings.bootstrap_* fields (V6). New owner-created
-- tables auto-inherit cp_runtime CRUD via V11's ALTER DEFAULT PRIVILEGES.
--
-- Secrets-at-rest (Design §2.5): no raw secret is stored. The auth-code+PKCE
-- `state`, PKCE `code_verifier` and OIDC `nonce` are NOT persisted — only a
-- SHA-256 of `state` (for single-use lookup); the verifier and nonce are DERIVED
-- server-side (HMAC over the raw `state` under an env-sourced key) and recomputed
-- at the callback, so a datastore-only compromise yields no usable secret.

-- ---------------------------------------------------------------------------
-- oidc_login (FR-AUTH-6) — transient auth-code + PKCE relying-party state. One
-- row per browser login attempt; single-use (consumed_at). Backs both the plain
-- web login and a device-flow approval (purpose='device' links device_flow).
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.oidc_login (
    id                 uuid        PRIMARY KEY,
    -- SHA-256 of the opaque, high-entropy `state` (raw never stored). Lookup key at
    -- the callback + single-use guard (UNIQUE). The PKCE verifier and the nonce are
    -- NOT stored: they are derived from the raw `state` under a server HMAC key.
    state_hash         text        NOT NULL UNIQUE
                                   CHECK (state_hash NOT LIKE '%PRIVATE KEY%'),
    purpose            text        NOT NULL DEFAULT 'web_login'
                                   CHECK (purpose IN ('web_login', 'device')),
    -- Set when purpose='device' (the approval binds this login to a device flow).
    device_flow_id     uuid        REFERENCES runtime.device_flow (id) ON DELETE CASCADE,
    -- Browser source IP captured when the login page was served (anti-phishing
    -- correlation input, §5.2). Validated by the shared format guard.
    source_ip          text        CHECK (source_ip IS NULL OR runtime.is_ip_or_cidr(source_ip)),
    status             text        NOT NULL DEFAULT 'pending'
                                   CHECK (status IN ('pending', 'completed', 'failed', 'expired')),
    resolved_identity  text,                                     -- set on success (never client-chosen)
    expires_at         timestamptz NOT NULL,
    consumed_at        timestamptz,                              -- single-use marker (atomic at callback)
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.oidc_login IS 'FR-AUTH-6: auth-code+PKCE relying-party state. state hash only; verifier/nonce derived (never stored). Single-use. Links a device_flow when purpose=device.';

CREATE INDEX idx_oidc_login_expires ON runtime.oidc_login (expires_at) WHERE status = 'pending';
CREATE INDEX idx_oidc_login_device_flow ON runtime.oidc_login (device_flow_id);

-- ---------------------------------------------------------------------------
-- device_flow anti-phishing correlation (§5.2, FR-AUTH-3). The approving
-- browser's source context is captured at the CP verification page and
-- correlated with the SSH source IP (device_flow.source_ip). Source IP is a
-- deny-only reducer (FR-AUTH-15): a mismatch is flagged + audited, never used as
-- positive identity evidence.
-- ---------------------------------------------------------------------------
ALTER TABLE runtime.device_flow
    ADD COLUMN approver_source_ip   text
        CHECK (approver_source_ip IS NULL OR runtime.is_ip_or_cidr(approver_source_ip)),
    ADD COLUMN approver_context     jsonb
        CHECK (approver_context IS NULL OR jsonb_typeof(approver_context) = 'object'),
    ADD COLUMN source_context_match boolean;
COMMENT ON COLUMN runtime.device_flow.approver_source_ip IS '§5.2 anti-phishing: the approving browser IP captured at the CP verification page.';
COMMENT ON COLUMN runtime.device_flow.source_context_match IS '§5.2: result of correlating the approving browser context with the SSH source IP (deny-only reducer, FR-AUTH-15).';

-- ---------------------------------------------------------------------------
-- auth_rate_limit (FR-AUTH-9) — durable fixed-window counter for the OTP-verify
-- and token endpoints. Keyed by an opaque bucket (e.g. "otp:verify:<source-ip>").
-- A DB-backed limiter holds across HA instances and restarts, unlike an in-memory
-- one. Reset is implicit: a request in a newer window overwrites window_start and
-- resets count (an atomic upsert).
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.auth_rate_limit (
    bucket       text        PRIMARY KEY,
    window_start timestamptz NOT NULL,
    count        integer     NOT NULL DEFAULT 0 CHECK (count >= 0),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.auth_rate_limit IS 'FR-AUTH-9: durable fixed-window rate-limit counters for OTP-verify + token endpoints (per-source-IP / per-identity bucket).';

-- ---------------------------------------------------------------------------
-- consumed_assertion (FR-AUTH-12) — single-use guard for OAuth private_key_jwt
-- client assertions (RFC 7523 §3): a client assertion's `jti` MUST NOT be
-- replayable within its lifetime. Store the SHA-256 of the jti (never the raw
-- assertion) with the assertion's own expiry; a repeat jti before expiry is a
-- replay and is rejected. A periodic prune drops rows past not_after.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.consumed_assertion (
    jti_hash   text        PRIMARY KEY
                           CHECK (jti_hash NOT LIKE '%PRIVATE KEY%'),
    subject    text        NOT NULL,                             -- the service-account/client id (audit legibility)
    not_after  timestamptz NOT NULL,                             -- the assertion's own exp
    created_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.consumed_assertion IS 'FR-AUTH-12 / RFC 7523: single-use guard for private_key_jwt client-assertion jti (hash only). Blocks assertion replay within its lifetime.';

CREATE INDEX idx_consumed_assertion_not_after ON runtime.consumed_assertion (not_after);
