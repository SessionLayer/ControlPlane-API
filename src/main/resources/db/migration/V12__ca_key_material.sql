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
-- credentials), RUNTIME not config. It references
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
    wrapped_key   bytea       NOT NULL                     -- KEK-encrypted CA private key (ciphertext; never plaintext)
                              -- ciphertext-only guard: reject a '-----BEGIN' PEM marker written into the blob
                              CHECK (octet_length(wrapped_key) > 0
                                     AND position('\x2d2d2d2d2d424547494e'::bytea in wrapped_key) = 0),
    iv            bytea       NOT NULL CHECK (octet_length(iv) = 12),  -- AES-GCM nonce is exactly 12 bytes
    public_key    bytea       NOT NULL,                    -- CA public key (X.509 SubjectPublicKeyInfo; public material)
    key_type      text        NOT NULL DEFAULT 'ecdsa-sha2-nistp256',
    version       bigint      NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE runtime.ca_key_material IS 'FR-CA-8: KEK-wrapped local-CA private key (ciphertext only) + public blob. KEK is env-sourced, never in the DB. Referenced by config.ca_config.key_reference = local:<id>.';

CREATE INDEX idx_ca_key_material_config ON runtime.ca_key_material (ca_config_id);

-- Crown-jewel hardening (F-ca-key-material-1): the restricted runtime role gets only
-- INSERT/SELECT (V11's ALTER DEFAULT PRIVILEGES gave it CRUD; revoke the destructive
-- verbs). Rotation writes a NEW row, so UPDATE/DELETE is never legitimately needed by
-- the app — a compromised app credential cannot delete/corrupt a wrapped CA key.
DO $grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON runtime.ca_key_material FROM cp_runtime';
        EXECUTE 'GRANT INSERT, SELECT ON runtime.ca_key_material TO cp_runtime';
    END IF;
END
$grant$;

-- Write-once provenance (defense in depth, mirrors recording_ref): once inserted, the
-- wrapped key / iv / public key / config binding may never change (owner path too).
CREATE OR REPLACE FUNCTION runtime.enforce_ca_key_material_write_once()
    RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.ca_config_id IS DISTINCT FROM OLD.ca_config_id
        OR NEW.wrapped_key IS DISTINCT FROM OLD.wrapped_key
        OR NEW.iv IS DISTINCT FROM OLD.iv
        OR NEW.public_key IS DISTINCT FROM OLD.public_key THEN
        RAISE EXCEPTION 'ca_key_material (ca_config_id/wrapped_key/iv/public_key) is write-once'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER ca_key_material_write_once
    BEFORE UPDATE ON runtime.ca_key_material
    FOR EACH ROW EXECUTE FUNCTION runtime.enforce_ca_key_material_write_once();
