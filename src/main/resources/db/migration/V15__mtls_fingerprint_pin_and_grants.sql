-- V15 — mTLS client-cert fingerprint pinning + token-grant least-privilege.
-- SessionLayer Control Plane, Session Four T4 hardening (M6, L5). Forward-only, additive.

-- 1. M6 — previous generation's client-cert SHA-256 fingerprint.
-- The sign/renew tiers pin the PRESENTED client certificate's fingerprint to the stored
-- gateway_identity fingerprint so a superseded (renewed-away) certificate stops
-- authenticating those tiers — making renew an effective rotation/compromise-recovery
-- primitive without waiting for the S10 CRL/OCSP/lock-push fan-out. To survive the
-- renew-ahead overlap, the pin tolerates {current, previous}: renew records the outgoing
-- fingerprint here. NULL for a freshly-enrolled (generation 0) identity. Public material.
ALTER TABLE runtime.gateway_identity ADD COLUMN prev_fingerprint text;
COMMENT ON COLUMN runtime.gateway_identity.prev_fingerprint IS
    'SHA-256 fingerprint of the previous-generation mTLS cert; pinned alongside fingerprint at the sign/renew tiers to survive renew-ahead overlap (M6). Public material.';

-- 2. L5 — least privilege on the single-use token tables.
-- Both tables are single-use via an UPDATE (mark consumed/used); cp_runtime never DELETEs a
-- token row. Drop the DELETE grant V14 issued (mirrors V12's write-once discipline).
DO $revoke$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'REVOKE DELETE ON runtime.gateway_enrollment_token FROM cp_runtime';
        EXECUTE 'REVOKE DELETE ON runtime.session_signing_token FROM cp_runtime';
    END IF;
END
$revoke$;
