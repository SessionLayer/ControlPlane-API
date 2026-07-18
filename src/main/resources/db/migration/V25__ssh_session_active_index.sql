-- V25 — index active-session lookups by identity. SessionLayer Control Plane.
--
-- FR-SESS-3 concurrency counting is on runtime.session_lease (idx_session_lease_live,
-- V9). This partial index serves the OTHER active-by-identity path: the config-API
-- session listing (SessionManagementService.list filters ssh_session by identity with
-- ended_at IS NULL for activeOnly), and it fills the gap left by idx_session_live (V5),
-- which is keyed on node_id, not identity. The finalize path now also stamps
-- ssh_session.ended_at, so these live rows are bounded. Non-breaking (additive index,
-- IF NOT EXISTS).

CREATE INDEX IF NOT EXISTS ix_ssh_session_active_identity
    ON runtime.ssh_session (identity) WHERE ended_at IS NULL;
