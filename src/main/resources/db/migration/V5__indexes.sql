-- V5 — Indexes for the documented query patterns.
-- SessionLayer Control Plane. Inline PK/UNIQUE constraints (V2/V3) already create
-- their own indexes; this file adds the secondary indexes the design's read paths
-- imply. Kept deliberately lean (no speculative indexing).

-- === Presence routing (Design §10.2 / FR-HA-2) =============================
-- "who owns node X" is the PK (node_id) lookup. The reverse — "which nodes does
-- gateway G own", used on Gateway failover/drain — needs this:
CREATE INDEX idx_presence_owning_gateway ON runtime.presence (owning_gateway);

-- === Audit search dimensions (FR-AUD-8, FR-AUD-9) ==========================
-- Auditors search by identity, node, time, source IP, capabilities, access model;
-- correlation joins the two trails by id.
CREATE INDEX idx_audit_actor        ON runtime.audit_event (actor);
CREATE INDEX idx_audit_subject      ON runtime.audit_event (subject);
CREATE INDEX idx_audit_node         ON runtime.audit_event (node_id);
CREATE INDEX idx_audit_occurred_at  ON runtime.audit_event (occurred_at);
CREATE INDEX idx_audit_source_ip    ON runtime.audit_event (source_ip);
CREATE INDEX idx_audit_access_model ON runtime.audit_event (access_model);
CREATE INDEX idx_audit_correlation  ON runtime.audit_event (correlation_id);
CREATE INDEX idx_audit_session      ON runtime.audit_event (session_id);
-- capability set membership search -> GIN on the array.
CREATE INDEX idx_audit_capabilities ON runtime.audit_event USING gin (capabilities);

-- === Session lookup / audit-by-session (Design §12A) =======================
CREATE INDEX idx_session_identity     ON runtime.ssh_session (identity);
CREATE INDEX idx_session_node         ON runtime.ssh_session (node_id);
CREATE INDEX idx_session_started_at   ON runtime.ssh_session (started_at);
CREATE INDEX idx_session_access_model ON runtime.ssh_session (access_model);
CREATE INDEX idx_session_gateway      ON runtime.ssh_session (gateway_id);
CREATE INDEX idx_session_jit_request  ON runtime.ssh_session (jit_request_id);

-- === Lock-set fetch (Design §6.3/§8.4 — pushed deny-list) ==================
-- Locks are fetched wholesale to push to Gateways; expiry filtering benefits from:
CREATE INDEX idx_lock_expires_at ON runtime.access_lock (expires_at);

-- === Foreign-key columns (Postgres does not auto-index these) ==============
CREATE INDEX idx_agent_identity_node   ON runtime.agent_identity (node_id);
CREATE INDEX idx_join_token_node       ON runtime.join_token (node_id);
CREATE INDEX idx_jit_request_target    ON runtime.jit_request (target_node_id);
CREATE INDEX idx_role_binding_role     ON config.role_binding (role_id);

-- === One ACTIVE credential per node (FR-JOIN-6) ============================
-- History rows (locked/revoked) may accumulate, but at most one active identity
-- per node. Partial unique index enforces it without blocking re-provision.
CREATE UNIQUE INDEX uq_agent_identity_active_per_node
    ON runtime.agent_identity (node_id) WHERE status = 'active';

-- === Operational lookups ===================================================
-- JIT approver queues (find pending requests) and node targeting exclusion.
CREATE INDEX idx_jit_request_state ON runtime.jit_request (state);
CREATE INDEX idx_jit_request_requester ON runtime.jit_request (requester);
CREATE INDEX idx_node_status ON runtime.node (status);
-- Credential-expiry / single-use sweeps.
CREATE INDEX idx_join_token_expires ON runtime.join_token (expires_at) WHERE consumed_at IS NULL;
CREATE INDEX idx_otp_expires ON runtime.otp (expires_at) WHERE used = false;
CREATE INDEX idx_pin_identity ON runtime.pin (identity);
