-- V20 — Access models: break-glass credentials + IdP-independent auth stores.
-- SessionLayer Control Plane, Session Thirteen. Forward-only, additive; V1-V19 unchanged.
--
-- The JIT + break-glass STATE model was front-loaded in V2/V3 (config.jit_policy,
-- config.breakglass_policy, runtime.jit_request, runtime.breakglass_activation,
-- ssh_session.access_model/jit_request_id/breakglass_activation_id). Session 13 wires
-- the BEHAVIOUR and adds only the IdP-independent break-glass authentication stores it
-- needs (Design §7, §5.2; FR-ACC-6):
--   1. runtime.breakglass_credential  — registered FIDO2 sk-ecdsa PUBLIC keys (primary).
--   2. runtime.breakglass_offline_code — pre-issued single-use hashed codes (fallback).
--   3. runtime.breakglass_token        — single-use Authorize authority minted at resolve.
--   4. runtime.breakglass_activation   — enriched with identity/source/target/credential.
--   5. config.platform_role            — new permission `breakglass:manage`.
--
-- New owner-created runtime tables auto-inherit cp_runtime CRUD via V11's ALTER DEFAULT
-- PRIVILEGES; the single-use stores REVOKE DELETE (consumed by UPDATE, never DELETE),
-- mirroring V15/V17. NO raw secret is stored: FIDO2 keys are PUBLIC; offline codes are
-- SHA-256 hashes; the breakglass_token is a hash. Source binding uses the shared
-- runtime.is_ip_or_cidr guard + lenient ::inet <<= reducer (deny-only, FR-AUTH-15).

-- 1. -------------------------------------------------------------------------
-- breakglass_credential — a registered break-glass FIDO2 `sk-ecdsa` PUBLIC key
-- (Design §5.2/§7, FR-ACC-6, the PRIMARY IdP-independent path). Mirrors runtime.pin:
-- keyed by SHA-256 fingerprint, source-agnostic (a hardware token travels), scoped to
-- allowed_principals and an optional node_selector, revocable (revoked_at) and
-- optionally expiring. PUBLIC material only — no private key ever at rest.
CREATE TABLE runtime.breakglass_credential (
    id                 uuid        PRIMARY KEY,
    key_fingerprint    text        NOT NULL UNIQUE,               -- SHA-256 of the sk-ecdsa public key (OpenSSH form)
    public_key         bytea       NOT NULL,                      -- OpenSSH sk-ecdsa-sha2-nistp256 wire pubkey (PUBLIC)
    sk_application      text,                                     -- FIDO2 application/rp-id embedded in the key (audit legibility)
    identity           text        NOT NULL,                      -- the break-glass operator identity this key resolves to
    allowed_principals text[]      NOT NULL DEFAULT ARRAY[]::text[], -- linux logins this credential is scoped to (deny-only reducer)
    node_selector      jsonb       CHECK (node_selector IS NULL OR jsonb_typeof(node_selector) = 'object'), -- optional node scope; NULL = fleet
    expires_at         timestamptz,                              -- optional expiry (NULL = no expiry; a hardware token is durable)
    revoked_at         timestamptz,                              -- revocation marker (admin removes the key from the break-glass set)
    created_by         text        NOT NULL,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.breakglass_credential IS 'FR-ACC-6 / §5.2: registered break-glass FIDO2 sk-ecdsa PUBLIC key (primary IdP-independent path). Public material only; revocable; scoped to allowed_principals + optional node_selector.';
CREATE INDEX idx_breakglass_credential_identity ON runtime.breakglass_credential (identity);

-- 2. -------------------------------------------------------------------------
-- breakglass_offline_code — pre-issued single-use break-glass code (Design §7,
-- FR-ACC-6, the IdP-independent FALLBACK). Mirrors runtime.otp: hash only (raw code
-- NEVER stored), ≥128-bit entropy, source-bound, atomic single-use via `used` under the
-- @Version lock. revoked_at lets an admin invalidate an unused batch without DELETE.
CREATE TABLE runtime.breakglass_offline_code (
    id                 uuid        PRIMARY KEY,
    code_hash          text        NOT NULL UNIQUE                -- SHA-256 of the code; the raw code is NEVER stored
                                   CHECK (code_hash NOT LIKE '%PRIVATE KEY%'),
    identity           text        NOT NULL,                      -- the break-glass operator identity (never client input)
    allowed_principals text[]      NOT NULL DEFAULT ARRAY[]::text[],
    node_selector      jsonb       CHECK (node_selector IS NULL OR jsonb_typeof(node_selector) = 'object'),
    source_cidr        text        CHECK (source_cidr IS NULL OR runtime.is_ip_or_cidr(source_cidr)),
    expires_at         timestamptz NOT NULL,
    used               boolean     NOT NULL DEFAULT false,        -- atomic mark-used (single-use, replay-rejected)
    used_at            timestamptz,
    revoked_at         timestamptz,                              -- admin batch-revoke without DELETE
    created_by         text        NOT NULL,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.breakglass_offline_code IS 'FR-ACC-6: pre-issued single-use break-glass code (IdP-independent fallback). Stores code_hash only; atomic single-use; source-bound; ≥128-bit entropy.';
CREATE INDEX idx_breakglass_offline_code_identity ON runtime.breakglass_offline_code (identity);

-- 3. -------------------------------------------------------------------------
-- breakglass_token — the single-use authority the CP mints on a successful break-glass
-- RESOLVE and consumes at Authorize (Design §7, §15). Mirrors runtime.recording_token:
-- hash only, bound to {gateway, identity, node, source_address, exp}, atomic single-use
-- under @Version. It ties a break-glass Authorize to a genuine credential resolution
-- performed by THIS gateway — a Gateway can never assert break-glass without one.
CREATE TABLE runtime.breakglass_token (
    id                 uuid        PRIMARY KEY,
    token_hash         text        NOT NULL UNIQUE,               -- hash of the token — the raw token is NEVER stored
    gateway_id         uuid        NOT NULL,                      -- snapshot of the resolving gateway_identity.id (no FK: runtime->runtime)
    identity           text        NOT NULL,                      -- the break-glass identity the credential resolved to
    node_id            uuid,                                      -- target node (advisory binding; empty for fleet-scoped)
    allowed_principals text[]      NOT NULL DEFAULT ARRAY[]::text[], -- scoped logins carried from the credential (deny-only reducer)
    source_address     text        CHECK (source_address IS NULL OR runtime.is_ip_or_cidr(source_address)),
    expires_at         timestamptz NOT NULL,
    used               boolean     NOT NULL DEFAULT false,        -- atomic mark-used (single-use, replay-rejected)
    used_at            timestamptz,
    version            bigint      NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.breakglass_token IS 'FR-ACC-6 / §15: single-use break-glass Authorize authority, minted at ResolveBreakglass*, bound to {gateway,identity,node,source,exp}. Hash only; atomic single-use.';
CREATE INDEX idx_breakglass_token_gateway ON runtime.breakglass_token (gateway_id);

-- 4. -------------------------------------------------------------------------
-- breakglass_activation enrichment (FR-ACC-6 / FR-AUD-7). The V3 table carried
-- principal/reason/alert_ref/review_status/reviewer + policy snapshot; add the identity,
-- source IP, target node, and resolving-credential reference so a post-hoc reviewer sees
-- the whole break-glass event without stitching from audit_event.
ALTER TABLE runtime.breakglass_activation
    ADD COLUMN identity       text,                                -- the break-glass operator identity
    ADD COLUMN source_ip      text CHECK (source_ip IS NULL OR runtime.is_ip_or_cidr(source_ip)),
    ADD COLUMN target_node_id uuid,                                -- the node the break-glass session targeted (snapshot; no FK)
    ADD COLUMN credential_ref text;                                -- which credential authenticated (fingerprint or offline-code id)
COMMENT ON COLUMN runtime.breakglass_activation.identity IS 'FR-ACC-6: the break-glass operator identity that authenticated (IdP-independent).';
COMMENT ON COLUMN runtime.breakglass_activation.credential_ref IS 'FR-ACC-6: the resolving credential reference (sk-ecdsa fingerprint or offline-code id); legibility for post-hoc review.';

-- 5. -------------------------------------------------------------------------
-- Platform permission `breakglass:manage` — gates break-glass credential registration
-- (FIDO2 key add/revoke) and offline-code issuance (FR-PADM-1, FR-API-5). JIT
-- approve/deny keeps the existing `request:approve` (V2/V18). Widen the CHECK the same
-- way V18 did for lock:read/lock:write: drop + recreate the named constraint with the
-- larger set (existing roles stay a subset). cp_runtime already has CRUD on
-- config.platform_role (V11), so no GRANT is needed.
ALTER TABLE config.platform_role DROP CONSTRAINT platform_role_permissions_check;
ALTER TABLE config.platform_role
    ADD CONSTRAINT platform_role_permissions_check
    CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll',
        'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export',
        'audit:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write', 'breakglass:manage']::text[]);

-- 6. -------------------------------------------------------------------------
-- Grants. V11's ALTER DEFAULT PRIVILEGES auto-grants cp_runtime CRUD on the three new
-- runtime tables. Mirror V15/V17 least-privilege on the SINGLE-USE stores: a code/token
-- row is consumed by an UPDATE (used=true), never DELETE, so drop DELETE there.
-- breakglass_credential keeps DELETE (an admin may remove a registration outright, in
-- addition to the soft revoked_at). Re-assert idempotently for legibility.
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.breakglass_credential TO cp_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON runtime.breakglass_offline_code TO cp_runtime';
        EXECUTE 'REVOKE DELETE ON runtime.breakglass_offline_code FROM cp_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON runtime.breakglass_token TO cp_runtime';
        EXECUTE 'REVOKE DELETE ON runtime.breakglass_token FROM cp_runtime';
    END IF;
END
$grant$;
