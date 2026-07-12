-- V19 — Agent join & renewable identity. SessionLayer Control Plane, Session Twelve.
-- Forward-only, additive; V1-V18 unchanged.
--
-- Session Twelve generalizes the S4 Gateway enrollment/renewal machinery for
-- per-node Agents (Design §8, FR-JOIN-1/3/4/6). The durable Agent credential is
-- the same renewable internal mTLS X.509 identity + generation counter the
-- Gateway uses (D25/D28), so the schema change is symmetric with V15's gateway
-- pinning column — one nullable column on the existing runtime.agent_identity
-- (created in V3). No new tables: the join methods reuse runtime.join_token (V3),
-- and the incident-response reuse of runtime.access_lock is from S10.

-- 1. -------------------------------------------------------------------------
-- prev_fingerprint — the previous generation's client-cert SHA-256 fingerprint,
-- pinned alongside fingerprint at renew so a superseded (renewed-away) certificate
-- stops authenticating, while tolerating the renew-ahead overlap {current, prev}.
-- The exact mirror of V15's gateway_identity.prev_fingerprint (M6). NULL for a
-- freshly-enrolled (generation 0) identity. Public material.
ALTER TABLE runtime.agent_identity ADD COLUMN prev_fingerprint text;
COMMENT ON COLUMN runtime.agent_identity.prev_fingerprint IS
    'SHA-256 fingerprint of the previous-generation mTLS cert; pinned alongside fingerprint at renew to survive renew-ahead overlap (M6). Public material.';

-- 2. -------------------------------------------------------------------------
-- Grants. V11 already granted cp_runtime SELECT/INSERT/UPDATE/DELETE on ALL
-- runtime tables (incl. agent_identity, join_token, node) plus default privileges
-- for future tables, so the agent-join write paths — agent_identity status flip
-- (UPDATE), node registration (INSERT/UPDATE), join_token issue/consume/revoke
-- (INSERT/UPDATE/DELETE), access_lock insert (SELECT/INSERT) — are already
-- covered, and the new prev_fingerprint column inherits the table-level grant.
-- V15 revoked DELETE only from the V14 token tables (gateway_enrollment_token /
-- session_signing_token), NOT from join_token, so join-token revoke (DELETE) is
-- available. Re-assert the join-token grants idempotently for legibility so this
-- migration is self-contained about the rights the agent-join API relies on.
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON runtime.join_token TO cp_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON runtime.agent_identity TO cp_runtime';
    END IF;
END
$grant$;
