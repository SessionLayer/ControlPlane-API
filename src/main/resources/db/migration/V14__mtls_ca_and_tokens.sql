-- V14 — internal mTLS CA + Gateway enrollment / session-signing tokens.
-- SessionLayer Control Plane, Session Four.
--
-- Adds the schema that Session Four's CP<->Gateway mTLS plane needs (Design §2A,
-- §8, §15; FR-BOOT-3, FR-CA-3, FR-JOIN-3/4). Forward-only, additive; V2-V13 are
-- unchanged. Three concerns:
--   1. The internal mTLS CA is an X.509 CA distinct from the three SSH CAs, so
--      config.ca_config.ca_kind gains a new value 'mtls' (expand/contract CHECK).
--   2. ca_key_material gains a nullable ca_certificate column so the self-signed
--      X.509 CA certificate (DER) is persisted alongside the KEK-wrapped key (SSH
--      CA rows leave it null). The V12 write-once hardening is extended to cover it.
--   3. Two single-use, hash-only token tables (mirroring join_token/otp, Design
--      §8.1): gateway_enrollment_token (bootstrap credential, single-use, short TTL)
--      and session_signing_token (the per-RPC session-bound authority, §15).

-- 1. ------------------------------------------------------------------------
-- Expand config.ca_config.ca_kind to admit the internal mTLS CA (expand/contract:
-- drop the inline CHECK by its auto-generated name, recreate with the wider set).
-- Existing rows (user/session/host) are unaffected.
ALTER TABLE config.ca_config DROP CONSTRAINT ca_config_ca_kind_check;
ALTER TABLE config.ca_config
    ADD CONSTRAINT ca_config_ca_kind_check CHECK (ca_kind IN ('user', 'session', 'host', 'mtls'));
COMMENT ON COLUMN config.ca_config.ca_kind IS 'user|session|host (SSH CAs) or mtls (the internal CP<->Gateway X.509 CA, S4).';

-- 2. ------------------------------------------------------------------------
-- The self-signed X.509 CA certificate (DER). NULL for SSH CA rows (whose trust is
-- an OpenSSH public key, not an X.509 cert); populated for the mtls CA so the CP can
-- present the trust chain (EnrollGatewayResponse.ca_chain) and reload the anchor.
ALTER TABLE runtime.ca_key_material ADD COLUMN ca_certificate bytea;
COMMENT ON COLUMN runtime.ca_key_material.ca_certificate IS 'X.509 CA certificate (DER) for X.509 CA rows (mtls); NULL for SSH CAs. Public material.';

-- Extend the V12 write-once guard to include ca_certificate: like wrapped_key/iv/
-- public_key it is set once at insert and immortal thereafter (CREATE OR REPLACE is
-- idempotent; the trigger itself is unchanged).
CREATE OR REPLACE FUNCTION runtime.enforce_ca_key_material_write_once()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.ca_config_id IS DISTINCT FROM OLD.ca_config_id
        OR NEW.wrapped_key IS DISTINCT FROM OLD.wrapped_key
        OR NEW.iv IS DISTINCT FROM OLD.iv
        OR NEW.public_key IS DISTINCT FROM OLD.public_key
        OR NEW.ca_certificate IS DISTINCT FROM OLD.ca_certificate THEN
        RAISE EXCEPTION 'ca_key_material (ca_config_id/wrapped_key/iv/public_key/ca_certificate) is write-once'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- 3a. -----------------------------------------------------------------------
-- runtime.gateway_enrollment_token — the operator-provisioned bootstrap credential
-- (Design §4.B, FR-JOIN-3). Single-use, short-TTL, self-destruct. Stores the token
-- HASH only (the raw token is never persisted), scoped to a single gateway_name.
CREATE TABLE runtime.gateway_enrollment_token (
    id           uuid        PRIMARY KEY,
    token_hash   text        NOT NULL UNIQUE,          -- hash of the token — the raw token is NEVER stored
    gateway_name text        NOT NULL,                 -- the stable Gateway name the token enrolls
    single_use   boolean     NOT NULL DEFAULT true,
    expires_at   timestamptz NOT NULL,
    consumed_at  timestamptz,                          -- set atomically on successful enroll (single-use)
    created_by   text,
    version      bigint      NOT NULL DEFAULT 0,       -- @Version optimistic lock (guards the consume race)
    created_at   timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.gateway_enrollment_token IS 'FR-JOIN-3 / Design §4.B: single-use, short-TTL Gateway enrollment token (hash only). Reusable JoinMethod shape for S12.';
CREATE INDEX idx_gateway_enrollment_token_gateway ON runtime.gateway_enrollment_token (gateway_name);

-- 3b. -----------------------------------------------------------------------
-- runtime.session_signing_token — the per-RPC session-bound authority (Design §15,
-- FR-CA-3). Single-use, bound to {gateway_id, session_id, node_id, principal, exp}.
-- Stores the token HASH only. S5/S8 will mint it from a real RBAC decision; this
-- session mints it via a minimal CP-internal path so the signing RPC is testable.
CREATE TABLE runtime.session_signing_token (
    id             uuid        PRIMARY KEY,
    token_hash     text        NOT NULL UNIQUE,        -- hash of the token — the raw token is NEVER stored
    gateway_id     uuid        NOT NULL,               -- snapshot of the owning gateway_identity.id (no FK: runtime->runtime snapshot)
    session_id     uuid        NOT NULL,               -- the SessionLayer session this cert is for
    node_id        uuid,                               -- the target node (optional at mint time)
    principal      text        NOT NULL,               -- the RBAC-resolved Linux login the cert certifies
    capabilities   text[]      NOT NULL DEFAULT ARRAY['shell', 'exec']::text[]
                               CHECK (capabilities <@ ARRAY['shell', 'exec', 'sftp', 'scp',
                                   'port_forward_local', 'port_forward_remote',
                                   'agent_forward', 'x11']::text[]),
    source_address text        CHECK (source_address IS NULL OR runtime.is_ip_or_cidr(source_address)),
    expires_at     timestamptz NOT NULL,
    used           boolean     NOT NULL DEFAULT false, -- atomic mark-used (single-use, replay-rejected)
    used_at        timestamptz,
    version        bigint      NOT NULL DEFAULT 0,      -- @Version optimistic lock (guards the consume race)
    created_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.session_signing_token IS 'Design §15 / FR-CA-3: single-use session-signing token bound to {gateway,session,node,principal,exp}. Hash only; atomic single-use.';
CREATE INDEX idx_session_signing_token_gateway ON runtime.session_signing_token (gateway_id);

-- 4. ------------------------------------------------------------------------
-- Grants. V11's ALTER DEFAULT PRIVILEGES already auto-grants CRUD on owner-created
-- tables to cp_runtime, so the two new token tables inherit SELECT/INSERT/UPDATE
-- (single-use marking is an UPDATE) automatically. Re-assert explicitly (idempotent)
-- so the intent is legible and the migration is self-contained. ca_certificate needs
-- no grant change (ca_key_material stays INSERT/SELECT-only, and the cert is written
-- at insert).
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.gateway_enrollment_token TO cp_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.session_signing_token TO cp_runtime';
    END IF;
END
$grant$;
