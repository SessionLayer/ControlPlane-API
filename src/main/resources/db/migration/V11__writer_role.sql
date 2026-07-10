-- V11 — non-owner CP runtime DB role (writer-role hardening). SessionLayer CP.
--
-- Closes the residual of F-append-only-1: the append-only + schema-boundary
-- guarantees must hold against a COMPROMISED APPLICATION DB CREDENTIAL, not only the
-- honest/ORM path the V4 trigger covers. A trigger cannot stop a role that OWNS the
-- table (ALTER TABLE ... DISABLE TRIGGER / DROP) or is a superuser
-- (session_replication_role = replica). The fix is to run the R2DBC runtime as a
-- non-owner, non-superuser role with least privilege, while Flyway migrations keep
-- running as the owner/DDL role (the S2 jdbc-flyway / r2dbc-runtime split).
--
-- This migration runs as the owner. It creates the restricted `cp_runtime` role and
-- grants it: CRUD on config.* and runtime.* EXCEPT runtime.audit_event, on which it
-- gets INSERT/SELECT only; EXECUTE on the helper functions; and default privileges so
-- future owner-created tables auto-grant. It gets NO CREATE, NO ownership, and cannot
-- ALTER/DROP/DISABLE TRIGGER. The runtime connects as this role (spring.r2dbc.username);
-- Flyway connects as the owner (spring.flyway.user). The dedicated IT WriterRoleIT
-- proves the negative capabilities against this credential.
--
-- Password: sourced from the Flyway placeholder ${cpRuntimePassword} (dev default set
-- in application.properties; MUST be overridden + rotated out-of-band in production).
-- Flyway checksums the raw file, so changing the placeholder value never causes a
-- checksum mismatch.

-- 1. The restricted role (idempotent; roles are cluster-global). Non-superuser,
--    non-createdb, non-createrole, non-bypassrls, non-owner.
DO $do$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cp_runtime') THEN
        CREATE ROLE cp_runtime NOLOGIN;
    END IF;
END
$do$;
ALTER ROLE cp_runtime WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '${cpRuntimePassword}';

-- 2. Schema usage (no CREATE — cannot add objects to either schema).
GRANT USAGE ON SCHEMA config, runtime TO cp_runtime;

-- 3. CONFIG: full CRUD (reconciler-scoped write + cold-start writes ca_config /
--    operator_settings). No DDL.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA config TO cp_runtime;

-- 4. RUNTIME: full CRUD, then lock audit_event down to INSERT/SELECT.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA runtime TO cp_runtime;
REVOKE UPDATE, DELETE, TRUNCATE ON runtime.audit_event FROM cp_runtime;

-- 4a. Lock every existing audit partition (seeded in V7, before this role existed)
--     to INSERT/SELECT — defense in depth so a direct-partition UPDATE/DELETE by a
--     compromised credential is also refused, not just access via the parent.
DO $lock$
DECLARE part record;
BEGIN
    FOR part IN
        SELECT c.relname
        FROM pg_inherits inh
        JOIN pg_class c ON c.oid = inh.inhrelid
        JOIN pg_class p ON p.oid = inh.inhparent
        JOIN pg_namespace n ON n.oid = p.relnamespace
        WHERE n.nspname = 'runtime' AND p.relname = 'audit_event'
    LOOP
        EXECUTE format('REVOKE ALL ON runtime.%I FROM cp_runtime', part.relname);
        EXECUTE format('GRANT INSERT, SELECT ON runtime.%I TO cp_runtime', part.relname);
    END LOOP;
END
$lock$;

-- 5. Sequences (belt-and-suspenders; identity columns need no explicit grant).
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA config, runtime TO cp_runtime;

-- 6. Functions the app invokes (validators, partition management, prune helpers).
GRANT EXECUTE ON FUNCTION runtime.is_ip_or_cidr(text) TO cp_runtime;
GRANT EXECUTE ON FUNCTION runtime.audit_ensure_partition(date) TO cp_runtime;
GRANT EXECUTE ON FUNCTION runtime.audit_ensure_partitions(date, integer) TO cp_runtime;
GRANT EXECUTE ON FUNCTION runtime.audit_prune_before(timestamptz) TO cp_runtime;
GRANT EXECUTE ON FUNCTION runtime.recording_prunable(timestamptz) TO cp_runtime;

-- 7. Future owner-created tables auto-grant CRUD to cp_runtime (so later sessions need
--    no re-grant). New audit partitions are corrected to INSERT/SELECT by
--    audit_ensure_partition (which REVOKE ALL + GRANT INSERT,SELECT after creating).
ALTER DEFAULT PRIVILEGES IN SCHEMA config
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cp_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA runtime
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cp_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA config
    GRANT USAGE, SELECT ON SEQUENCES TO cp_runtime;
ALTER DEFAULT PRIVILEGES IN SCHEMA runtime
    GRANT USAGE, SELECT ON SEQUENCES TO cp_runtime;

-- 8. Read-only visibility into Flyway's migration history (ops/health can report the
--    schema version; no secrets). Guarded so a non-default history table/schema is a no-op.
DO $fh$
BEGIN
    IF to_regclass('public.flyway_schema_history') IS NOT NULL THEN
        EXECUTE 'GRANT SELECT ON public.flyway_schema_history TO cp_runtime';
    END IF;
END
$fh$;

COMMENT ON ROLE cp_runtime IS 'SessionLayer CP restricted runtime role (F-append-only-1): CRUD on config/runtime except audit_event (INSERT/SELECT only); no DDL/ownership. Runtime connects as this; Flyway as the owner.';
