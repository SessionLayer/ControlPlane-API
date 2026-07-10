-- V9 — model-gap RUNTIME tables. SessionLayer Control Plane.
-- Closes F-model-deferrals-1 items F-DM-12/13/14/8 (runtime side). Schema only;
-- behaviour is the owning later session (S6/S7/node-lifecycle). Round-trip + constraint
-- + schema-presence gates in the S3 IT suite.

-- ---------------------------------------------------------------------------
-- service_account_credential (F-DM-12, FR-AUTH-12) — issued machine-consumer creds.
-- config.service_account is the DEFINITION; the issued credential (rotatable,
-- revocable) is runtime. runtime->config is a SNAPSHOT (plain uuid + name, no FK).
-- Stores a HASH/reference only, never a raw secret.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.service_account_credential (
    id                   uuid        PRIMARY KEY,
    service_account_id   uuid        NOT NULL,                    -- snapshot ref to config.service_account.id (NO FK)
    service_account_name text        NOT NULL,                   -- snapshot of the name (legible after config GC)
    credential_type      text        NOT NULL
                                     CHECK (credential_type IN ('private_key_jwt', 'mtls', 'client_secret')),
    -- secret_hash: hash of a client_secret, OR a public-key/cert fingerprint reference
    -- for private_key_jwt/mtls. NEVER a raw secret or private key (content guard).
    secret_hash          text        NOT NULL
                                     CHECK (secret_hash NOT LIKE '%PRIVATE KEY%' AND secret_hash NOT LIKE '%BEGIN %'),
    fingerprint          text,
    status               text        NOT NULL DEFAULT 'active'
                                     CHECK (status IN ('active', 'revoked')),
    issued_at            timestamptz NOT NULL,
    not_after            timestamptz,
    revoked_at           timestamptz,
    revoked_reason       text,
    revoked_by           text,
    version              bigint      NOT NULL DEFAULT 0,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT sac_validity_ordered CHECK (not_after IS NULL OR not_after > issued_at)
);
COMMENT ON TABLE runtime.service_account_credential IS 'FR-AUTH-12: issued machine-consumer credential (rotatable/revocable). Hash/reference only; service_account_id is a snapshot (no FK to config).';

CREATE INDEX idx_sac_service_account ON runtime.service_account_credential (service_account_id);
CREATE UNIQUE INDEX uq_sac_active_secret_hash
    ON runtime.service_account_credential (secret_hash) WHERE status = 'active';

-- ---------------------------------------------------------------------------
-- device_flow (F-DM-13, FR-AUTH-3/6, Design §5.2/§15) — OIDC device-flow state.
-- Stores HASHes of the device_code/user_code (never raw). connection_binding is the
-- 1:1 device_code<->connection anti-phishing binding (§15). Behaviour is S6.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.device_flow (
    id                 uuid        PRIMARY KEY,
    device_code_hash   text        NOT NULL UNIQUE,               -- hash of the device_code (raw never stored)
    user_code_hash     text        NOT NULL,                      -- hash of the user-facing code
    identity           text,                                      -- resolved after IdP auth (null while pending)
    status             text        NOT NULL DEFAULT 'pending'
                                   CHECK (status IN ('pending', 'authorized', 'denied', 'expired')),
    -- 1:1 device_code<->SSH-connection binding (anti-phishing, §5.2/§15): the single
    -- connection permitted to consume this flow. A value/reference, not a key.
    connection_binding text,
    source_ip          text        CHECK (source_ip IS NULL OR runtime.is_ip_or_cidr(source_ip)),
    interval_seconds   integer     NOT NULL DEFAULT 5 CHECK (interval_seconds > 0),
    expires_at         timestamptz NOT NULL,
    last_polled_at     timestamptz,
    authorized_at      timestamptz,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.device_flow IS 'F-DM-13 / FR-AUTH-3: RFC 8628 device-flow state + 1:1 device_code<->connection anti-phishing binding (§15). Stores hashes only. Behaviour S6.';

CREATE INDEX idx_device_flow_expires ON runtime.device_flow (expires_at) WHERE status = 'pending';

-- ---------------------------------------------------------------------------
-- node_host_key (F-DM-14, FR-CONN-5, Design §9.3) — enrollment-anchored node host
-- identity so inner-leg host verification is NEVER TOFU. Primary: a host-CA-signed
-- host cert (host_cert_ref); fallback: an explicitly pinned host key (public_key +
-- fingerprint). Public material only (a host public key / fingerprint is not secret).
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.node_host_key (
    id            uuid        PRIMARY KEY,
    node_id       uuid        NOT NULL REFERENCES runtime.node (id) ON DELETE CASCADE,
    key_type      text        NOT NULL
                              CHECK (key_type IN ('ssh-ed25519', 'ecdsa-sha2-nistp256',
                                  'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-256', 'rsa-sha2-512')),
    public_key    text        NOT NULL CHECK (public_key NOT LIKE '%PRIVATE KEY%'),  -- OpenSSH public key line (public material)
    fingerprint   text        NOT NULL,                           -- SHA256:... fingerprint
    host_cert_ref text        CHECK (host_cert_ref IS NULL OR host_cert_ref NOT LIKE '%PRIVATE KEY%'),  -- host-CA-signed cert reference (primary path)
    source        text        NOT NULL DEFAULT 'pinned_key'
                              CHECK (source IN ('host_ca', 'pinned_key')),  -- verification anchor (FR-CONN-5)
    verified_at   timestamptz,                                    -- when the host identity was anchored at enrollment
    version       bigint      NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (node_id, fingerprint)
);
COMMENT ON TABLE runtime.node_host_key IS 'F-DM-14 / FR-CONN-5: enrollment-anchored node host identity (host-CA cert primary, pinned key fallback) so inner-leg host verification is never TOFU. Public material only.';

CREATE INDEX idx_node_host_key_node ON runtime.node_host_key (node_id);

-- ---------------------------------------------------------------------------
-- session_lease (F-DM-8, FR-SESS-3) — cluster-wide concurrency primitive. One live
-- lease per active session; per-identity concurrency = count of unreleased leases.
-- The enforcement semaphore/lease-acquire logic is S7; this is the durable primitive.
-- ---------------------------------------------------------------------------
CREATE TABLE runtime.session_lease (
    id           uuid        PRIMARY KEY,
    identity     text        NOT NULL,
    session_id   uuid        REFERENCES runtime.ssh_session (id) ON DELETE SET NULL,
    gateway_name text,
    acquired_at  timestamptz NOT NULL,
    expires_at   timestamptz,                                     -- lease safety TTL (reaped if a Gateway dies)
    released_at  timestamptz,                                     -- set when the session ends
    version      bigint      NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.session_lease IS 'F-DM-8 / FR-SESS-3: durable per-identity concurrency lease (count unreleased leases = live sessions). Enforcement semaphore is S7.';

-- Live-lease-per-identity count (concurrency) must not seq-scan lease history.
CREATE INDEX idx_session_lease_live ON runtime.session_lease (identity) WHERE released_at IS NULL;
CREATE INDEX idx_session_lease_session ON runtime.session_lease (session_id);
