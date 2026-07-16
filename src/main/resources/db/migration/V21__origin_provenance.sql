-- V21 — origin provenance is api|ui|default (drop 'git'). SessionLayer CP, Session 17.
--
-- Owner decision (2026-07-15): external config automation was descoped — config is
-- managed via UI + API over Postgres, the single source of truth (Design D11). The
-- `origin` column stays as generic provenance (which admin surface last wrote a row),
-- but its fourth legacy value can no longer occur, so this migration tightens the
-- CHECK to IN ('api', 'ui', 'default') on every config table that carries `origin`.
--
-- Expand/contract, lossless: no row ever carried the dropped value (no writer for it
-- was built), so DROP + re-ADD the column CHECK is safe with no data rewrite. The
-- config/runtime schema split is retained — it is the general config-vs-runtime
-- boundary that backs the cp_runtime role.
--
-- Postgres names a column CHECK `<table>_<column>_check`; each is dropped and re-added
-- explicitly so the constraint name and definition stay greppable.

ALTER TABLE config.node_policy
    DROP CONSTRAINT node_policy_origin_check,
    ADD CONSTRAINT node_policy_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.dp_rule
    DROP CONSTRAINT dp_rule_origin_check,
    ADD CONSTRAINT dp_rule_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.platform_role
    DROP CONSTRAINT platform_role_origin_check,
    ADD CONSTRAINT platform_role_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.role_binding
    DROP CONSTRAINT role_binding_origin_check,
    ADD CONSTRAINT role_binding_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.ca_config
    DROP CONSTRAINT ca_config_origin_check,
    ADD CONSTRAINT ca_config_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.capability_def
    DROP CONSTRAINT capability_def_origin_check,
    ADD CONSTRAINT capability_def_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.jit_policy
    DROP CONSTRAINT jit_policy_origin_check,
    ADD CONSTRAINT jit_policy_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.breakglass_policy
    DROP CONSTRAINT breakglass_policy_origin_check,
    ADD CONSTRAINT breakglass_policy_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.service_account
    DROP CONSTRAINT service_account_origin_check,
    ADD CONSTRAINT service_account_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.operator_settings
    DROP CONSTRAINT operator_settings_origin_check,
    ADD CONSTRAINT operator_settings_origin_check CHECK (origin IN ('api', 'ui', 'default'));

ALTER TABLE config.session_limit_policy
    DROP CONSTRAINT session_limit_policy_origin_check,
    ADD CONSTRAINT session_limit_policy_origin_check CHECK (origin IN ('api', 'ui', 'default'));
