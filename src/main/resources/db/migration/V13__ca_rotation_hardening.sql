-- V13 — CA rotation hardening. SessionLayer Control Plane, Session Three.
--
-- Closes R-ROT-2: without a uniqueness guard on the `incoming` state, two concurrent
-- (or retried) beginRotation calls for the same CA kind create two `incoming` rows;
-- promote would then pick one arbitrarily and leave the other `incoming` forever — a
-- never-expiring CA key stuck in the trusted set (incoming is trusted) with no lifecycle
-- to remove it (drain only touches `outgoing`). Mirror the active-per-kind partial-unique
-- index (V5) so a rotation cannot start twice.

CREATE UNIQUE INDEX uq_ca_config_incoming_per_kind
    ON config.ca_config (ca_kind) WHERE rotation_state = 'incoming';
