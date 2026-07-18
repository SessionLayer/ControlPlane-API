-- V25 — index the FR-SESS-3 per-identity live-session count. SessionLayer Control
-- Plane.
--
-- Authorize counts an identity's live sessions (ended_at IS NULL AND grant_expiry
-- > now) on every standing/JIT allow to enforce the concurrent-session cap. A
-- partial index on identity over only the live rows keeps that count off a
-- sequential scan as session history accumulates. Non-breaking (additive index,
-- IF NOT EXISTS).

CREATE INDEX IF NOT EXISTS ix_ssh_session_active_identity
    ON runtime.ssh_session (identity) WHERE ended_at IS NULL;
