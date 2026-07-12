-- V18 — Lock CRUD platform permissions. SessionLayer Control Plane, Session Ten.
-- Forward-only, additive; V1-V17 unchanged.
--
-- Session Ten adds the incident-response lock CRUD (Design §8.3; FR-LOCK-1/2),
-- platform-RBAC gated by two new permissions: lock:read (list) and lock:write
-- (create/release). The config.platform_role.permissions column CHECK-constrains
-- the allowed permission vocabulary (V2), so it must widen to admit the two new
-- strings — otherwise a platform-admin role carrying every PlatformPermissions.ALL
-- entry (incl. the first-admin bootstrap role) would violate the CHECK.
--
-- The V2 constraint was created inline/anonymous; Postgres named it
-- platform_role_permissions_check (mirrors the V14 ca_config_ca_kind_check
-- precedent). Drop + recreate it with the widened set. No data changes: existing
-- roles remain a subset of the (now larger) allowed set. cp_runtime already holds
-- CRUD on config.platform_role (V11), so no GRANT is needed.

ALTER TABLE config.platform_role DROP CONSTRAINT platform_role_permissions_check;
ALTER TABLE config.platform_role
    ADD CONSTRAINT platform_role_permissions_check
    CHECK (permissions <@ ARRAY['rbac:read', 'rbac:write', 'node:enroll',
        'node:quarantine', 'node:remove', 'ca:manage', 'ca:rotate',
        'request:approve', 'recording:replay', 'recording:export',
        'audit:read', 'user:manage', 'settings:write',
        'lock:read', 'lock:write']::text[]);
