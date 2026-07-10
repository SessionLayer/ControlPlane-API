-- V12 — local-CA KEK-wrapped key material (RUNTIME). SessionLayer Control Plane.
--
-- Part A / FR-CA-8, Design §14: the local CA backend generates an ECDSA P-256 key
-- and envelope-encrypts the PRIVATE key with an operator KEK. Only the WRAPPED
-- (encrypted) key is persisted here, plus the public key blob (public material).
-- The KEK itself is sourced from the environment at runtime (never the DB), so a
-- DB-only compromise (even the restricted runtime role) yields ciphertext it cannot
-- unwrap. `config.ca_config.key_reference` = 'local:<this row id>'.
--
-- Placement: RUNTIME. This is generated operational secret material (like issued
-- credentials), never Git-reconciled; the reconciler must not touch it. It references
-- config.ca_config by a SNAPSHOT id (no hard FK across runtime->config), consistent
-- with the model. Cleaned up with its config by ca_config_id lookup.

CREATE TABLE runtime.ca_key_material (
    id            uuid        PRIMARY KEY,
    ca_config_id  uuid        NOT NULL UNIQUE,             -- snapshot ref to config.ca_config.id (NO FK)
    ca_config_name text       NOT NULL,                    -- snapshot of the CA config name
    wrap_algorithm text       NOT NULL DEFAULT 'AES-256-GCM'
                              CHECK (wrap_algorithm IN ('AES-256-GCM')),
    kek_reference text        NOT NULL                     -- which KEK wrapped it (reference, never the KEK)
                              CHECK (kek_reference NOT LIKE '%PRIVATE KEY%'),
    wrapped_key   bytea       NOT NULL,                    -- KEK-encrypted CA private key (ciphertext; never plaintext)
    iv            bytea       NOT NULL,                    -- AES-GCM nonce (12 bytes)
    public_key    bytea       NOT NULL,                    -- CA public key SSH blob (public material)
    key_type      text        NOT NULL DEFAULT 'ecdsa-sha2-nistp256',
    version       bigint      NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.ca_key_material IS 'FR-CA-8: KEK-wrapped local-CA private key (ciphertext only) + public blob. KEK is env-sourced, never in the DB. Referenced by config.ca_config.key_reference = local:<id>.';

CREATE INDEX idx_ca_key_material_config ON runtime.ca_key_material (ca_config_id);
