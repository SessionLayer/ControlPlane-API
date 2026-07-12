-- V17 — Session recording: customer-key config + single-use recording token.
-- SessionLayer Control Plane, Session Nine. Forward-only, additive; V1-V16 unchanged.
--
-- Two concerns (Design §12/§12A/§15; FR-AUD-1/2/3/6/9, FR-DATA-2):
--   1. config.operator_settings gains the operator-configured CUSTOMER encryption
--      key material (PUBLIC half only — the CP never holds the private key, §15
--      crown-jewels) plus recording retention/mode knobs. When no customer key is
--      configured, BeginRecording fails closed (keystroke capture is always on, so
--      encryption is mandatory, FR-AUD-2).
--   2. runtime.recording_token — the SECOND single-use, session-bound authority
--      minted at Authorize ALLOW alongside session_signing_token, authorising
--      exactly one Recording.BeginRecording call (hash only; atomic single-use,
--      replay-rejected). A dedicated table (not a purpose column on
--      session_signing_token) keeps this additive and isolated from the S5 signing
--      token entity/service.

-- 1. ------------------------------------------------------------------------
-- Customer encryption key + recording policy on the operator_settings singleton.
--   * recording_customer_public_key: DER SubjectPublicKeyInfo of the customer EC
--     P-256 (ECIES) or RSA (RSA-OAEP) PUBLIC key. NULLABLE — when NULL, recording
--     is un-provisioned and BeginRecording fails closed (never stores keystrokes in
--     the clear). PUBLIC material only, so no reference/PEM content guard is needed
--     (it is DER bytes, not a pasted private key).
--   * recording_key_seal_algorithm: how the per-recording AES-256-GCM data key is
--     sealed to the customer key. ECIES P-256 is the portable default.
--   * recording_key_ref: the operator's opaque reference to the key, persisted into
--     recording_ref.encryption_key_ref (never key material) so replay (S15) can
--     locate the customer unwrap path.
--   * recording_retention_days: object-lock retain-until + recording_ref retention
--     window (FR-AUD-6). >= 0.
--   * recording_strict_default: reserved operator knob for per-node recording-required
--     policy; recording stays mandatory + fail-closed in S9 regardless.
ALTER TABLE config.operator_settings
    ADD COLUMN recording_customer_public_key bytea,
    ADD COLUMN recording_key_seal_algorithm  text        NOT NULL DEFAULT 'ecies_p256'
                                             CHECK (recording_key_seal_algorithm IN ('ecies_p256', 'rsa_oaep_sha256')),
    ADD COLUMN recording_key_ref             text        CHECK (recording_key_ref IS NULL
                                             OR (recording_key_ref NOT LIKE '%PRIVATE KEY%'
                                                 AND recording_key_ref NOT LIKE '%BEGIN %')),
    ADD COLUMN recording_retention_days      integer     NOT NULL DEFAULT 365 CHECK (recording_retention_days >= 1),
    ADD COLUMN recording_strict_default      boolean     NOT NULL DEFAULT true;

COMMENT ON COLUMN config.operator_settings.recording_customer_public_key IS 'FR-AUD-2 / §15: customer PUBLIC key (DER SubjectPublicKeyInfo) the Gateway seals the per-recording data key to. NULL => recording un-provisioned => BeginRecording fails closed. Public material only (the CP never holds the private half).';
COMMENT ON COLUMN config.operator_settings.recording_key_seal_algorithm IS 'How the per-recording data key is sealed to the customer key: ecies_p256 (default) | rsa_oaep_sha256.';
COMMENT ON COLUMN config.operator_settings.recording_key_ref IS 'Operator reference to the customer key (persisted into recording_ref.encryption_key_ref; never key material).';
COMMENT ON COLUMN config.operator_settings.recording_retention_days IS 'FR-AUD-6: recording retention window (object-lock retain-until + recording_ref.retention_until).';

-- 2. ------------------------------------------------------------------------
-- runtime.recording_token — single-use BeginRecording authority (Design §12/§15,
-- FR-AUD-1). Bound to {gateway_id, session_id, node_id, principal, exp}, mirroring
-- session_signing_token. Stores the token HASH only; atomic single-use via `used`
-- under the @Version optimistic lock (replay loses the race).
CREATE TABLE runtime.recording_token (
    id             uuid        PRIMARY KEY,
    token_hash     text        NOT NULL UNIQUE,        -- hash of the token — the raw token is NEVER stored
    gateway_id     uuid        NOT NULL,               -- snapshot of the owning gateway_identity.id (no FK: runtime->runtime snapshot)
    session_id     uuid        NOT NULL,               -- the SessionLayer session this recording is for
    node_id        uuid,                               -- the target node (advisory binding)
    principal      text        NOT NULL,               -- the RBAC-resolved Linux login (advisory binding)
    source_address text        CHECK (source_address IS NULL OR runtime.is_ip_or_cidr(source_address)),
    expires_at     timestamptz NOT NULL,
    used           boolean     NOT NULL DEFAULT false, -- atomic mark-used (single-use, replay-rejected)
    used_at        timestamptz,
    version        bigint      NOT NULL DEFAULT 0,      -- @Version optimistic lock (guards the consume race)
    created_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.recording_token IS 'Design §12/§15 / FR-AUD-1: single-use BeginRecording token bound to {gateway,session,node,principal,exp}. Hash only; atomic single-use. Minted at Authorize ALLOW alongside session_signing_token.';
CREATE INDEX idx_recording_token_gateway ON runtime.recording_token (gateway_id);

-- 3. ------------------------------------------------------------------------
-- Hash-chain head-read index. AuditWriter reads the current chain head with
-- `... WHERE record_hash IS NOT NULL ORDER BY seq DESC LIMIT 1` on every audit
-- write (under the chain advisory lock), so this partial index keeps that O(1).
-- Safe as a plain (non-CONCURRENT) CREATE even though audit_event may be populated:
-- the partial predicate matches only rows the S9 writer stamps, and every row that
-- exists at migration time predates S9 with record_hash = NULL, so the index is
-- EMPTY at creation. Propagates to every audit_event partition.
CREATE INDEX idx_audit_chain_head ON runtime.audit_event (seq DESC) WHERE record_hash IS NOT NULL;

-- Grants. V11's ALTER DEFAULT PRIVILEGES auto-grants CRUD on owner-created runtime
-- tables to cp_runtime, so recording_token inherits SELECT/INSERT/UPDATE/DELETE.
-- Mirror V15's least-privilege on the single-use token tables: the row is consumed by
-- an UPDATE (used=true), never DELETEd, so drop DELETE. Re-assert the rest explicitly
-- (idempotent) so the intent is legible. The operator_settings ALTER above needs no
-- re-grant (adding columns to an existing table preserves its grants).
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON runtime.recording_token TO cp_runtime';
        EXECUTE 'REVOKE DELETE ON runtime.recording_token FROM cp_runtime';
    END IF;
END
$grant$;
