# SessionLayer Control Plane — Data Model (Session Two freeze)

> **Status:** frozen for Session Two (the schema-foundation session). This document is a **contract** that
> later sessions (S3–S16) build on. It records the decisions behind the Flyway migrations (`V2+`) and the
> R2DBC entity/repository layer. The authoritative shape lives in the **migrations**
> (`src/main/resources/db/migration`), per Design §12A ("the authoritative shape lives in migrations"); this
> file explains *why* the schema is shaped the way it is.
>
> Source specs: `../../Docs/01-Design.md` §12A (core data model), §13 (config-vs-runtime boundary), §6/§7/§8/
> §10.2/§12; `../../Docs/02-Requirements.md` **FR-DATA-1/2** plus the entity-touching FRs. Specs win on conflict.

---

## 1. The load-bearing boundary: CONFIG vs RUNTIME (structural)

The single most important property of this schema is the **config-vs-runtime partition** (Design §13,
FR-DATA-1), because the GitOps reconciler (S16) relies on it for safety: the reconciler touches **CONFIG
only** and must **never** touch RUNTIME (locks, sessions, grants, issuance records, presence…).

**Decision — make the boundary structural with two Postgres schemas:**

| | Postgres schema | Reconciled by GitOps? | `origin` column? |
|---|---|---|---|
| **CONFIG** | `config` | Yes (Git-reconcilable) | **Yes**, on every table |
| **RUNTIME** | `runtime` | **Never** | No |

Rationale for two schemas (over a single schema with a naming convention):
- The boundary becomes **enforceable by Postgres role grants** later: S16 can run its reconciler under a role
  with write access to `config.*` and only read (or no) access to `runtime.*`, so a reconciler bug *cannot*
  physically mutate a lock or a session. A naming convention gives no such guarantee.
- It is **self-documenting**: `runtime.access_lock` tells any reader "the reconciler may not touch this".
- Flyway's `flyway_schema_history` stays in `public` (the connection default schema); we never place app
  tables in `public`.

**`lock` is RUNTIME and API-only.** `runtime.access_lock` carries no `origin` column and is documented
API-only (FR-API-3): a committed `Lock` kind MUST be rejected by the reconciler. "Deny now and keep it" is a
first-class runtime Lock, never a Git edit to a role.

**`origin` on every config row:** `origin text NOT NULL DEFAULT 'default' CHECK (origin IN
('git','api','ui','default'))` (FR-DATA-1, FR-API-4). It disambiguates ownership within CONFIG so Git-owned
drift can be reverted loudly.

---

## 2. Primary keys — app-generated UUIDv7

**Decision:** every table's PK is a `uuid`, **generated application-side as UUIDv7** (`io.sessionlayer.
controlplane.data.Uuids#v7`). One exception: `runtime.presence` is keyed by its `node_id` (1:1 with `node`).

- **UUIDv7** (48-bit Unix-ms timestamp prefix + random) gives **time-ordered index locality** on the
  high-write tables (`audit_event`, `ssh_session`, `presence`, `jit_request`) — new rows cluster at the right
  edge of the B-tree instead of scattering like UUIDv4. Design §4.2 recommends exactly this.
- **App-side, not DB-side:** we do **not** use `gen_random_uuid()` / `pgcrypto`. No DB extension is required
  by this schema at all (keeps cold-start simple; avoids the `pgcrypto`/PG-version coupling).
- **The R2DBC "is-new" problem (Design §7.2):** because the id is client-assigned (non-null before insert),
  Spring Data R2DBC would treat a fresh entity as an *update*. We solve this with an **`@Version Long
  version`** column on every entity: Spring determines "new" by `version == null`, so a fresh insert with a
  client-set UUID inserts correctly. This is proven by `...IsNew...` tests.
- **Bonus — optimistic concurrency for free:** the same `@Version` column guards the generation-counter
  renewal race on `agent_identity`/`gateway_identity` (Design §8.2): a concurrent renewal fails with
  `OptimisticLockingFailureException` rather than silently regressing `generation`. A DB-level
  `BEFORE UPDATE` trigger *also* rejects any `generation` decrease (defense in depth). See §7.

---

## 3. Timestamps — `timestamptz`, always UTC → Java `Instant`

- All time columns are `timestamptz` (Design §12.x, FR-BOOT-4: audit timestamps are UTC). Java type is
  **`java.time.Instant`** (an absolute instant, zone-free) — r2dbc-postgresql 1.1.1 ships a native
  `InstantCodec` for `timestamptz`, so **no converter is needed** and there is no offset-equality hazard.
- **Bookkeeping vs semantic time.** `created_at`/`updated_at` are bookkeeping, managed by Spring Data R2DBC
  auditing (`@EnableR2dbcAuditing` + `@CreatedDate`/`@LastModifiedDate`) with a custom `DateTimeProvider`
  returning `Instant.now()` (UTC). **Domain** timestamps that carry meaning — `audit_event.occurred_at`,
  `ssh_session.started_at`/`ended_at`, `*.expires_at`, `presence.last_seen`, `jit_request.requested_at` — are
  set explicitly by the writer, never by auditing.
- Columns keep a `DEFAULT now()` where a raw/`psql` insert could otherwise miss a bookkeeping value, but the
  application always supplies the value (auditing fills it), so R2DBC never sends a stray `NULL`.

---

## 4. Enums — `text` + `CHECK`, never native `ENUM`

**Decision:** closed value sets are `text` columns with an inline `CHECK (col IN (...))`, **not** native
Postgres `ENUM` types. Native enums are painful under expand/contract (`ALTER TYPE ... ADD VALUE` cannot run
in a transaction, values can't be removed, ordering is fixed) — a `CHECK` is edited by an ordinary additive
migration. The authoritative value sets (later sessions MUST stay aligned):

| Domain | Column(s) | Allowed values | Default |
|---|---|---|---|
| origin | config `*.origin` | `git`, `api`, `ui`, `default` | `default` |
| connector kind | `node_policy.connector_kind`, `node.connector_kind` | `agent`, `agentless` | — |
| rule effect | `dp_rule.effect` | `allow`, `deny` | — |
| lock mode | `access_lock.mode` | `strict`, `best_effort` | — |
| access model | `ssh_session.access_model`, `audit_event.access_model` | `standing`, `jit`, `breakglass` | — |
| JIT state | `jit_request.state` | `REQUESTED`, `PENDING_APPROVAL`, `APPROVED`, `DENIED`, `EXPIRED`, `ACTIVE`, `REVOKED` | `REQUESTED` |
| identity/credential status | `agent_identity.status`, `gateway_identity.status` | `active`, `locked`, `revoked` | `active` |
| join method | `agent_identity.join_method`, `gateway_identity.join_method`, `join_token.join_method` | `token`, `oidc`, `mtls` | — |
| CA kind | `ca_config.ca_kind` | `user`, `session`, `host` | — |
| CA backend | `ca_config.backend` | `local`, `aws_kms`, `azure_keyvault`, `vault` | — |
| CA algorithm | `ca_config.algorithm` | `ecdsa-p256`, `ecdsa-p384`, `ed25519`, `rsa-2048`, `rsa-4096` | `ecdsa-p256` (FR-CA-4) |
| CA rotation state | `ca_config.rotation_state` | `incoming`, `active`, `outgoing`, `expired` | `active` (FR-CA-7) |
| capability | element of every capability set | `shell`, `exec`, `sftp`, `scp`, `port_forward_local`, `port_forward_remote`, `agent_forward`, `x11` | `shell`,`exec` |
| audit outcome | `audit_event.outcome` | `success`, `failure`, `denied`, `error` | — |
| node status | `node.status` | `pending`, `active`, `quarantined`, `removed` | `pending` |
| node health | `node.health` | `unknown`, `healthy`, `unhealthy`, `unreachable` | `unknown` |
| WORM mode | `recording_ref.worm_mode` | `compliance`, `governance` | — (nullable) |
| break-glass auth path | `breakglass_policy.auth_path` | `fido2`, `offline_code` | `fido2` |
| break-glass review | `breakglass_activation.review_status` | `pending`, `reviewed` | `pending` |
| SA auth method | `service_account.auth_method` | `private_key_jwt`, `mtls`, `client_secret` | `private_key_jwt` |
| role-binding subject | `role_binding.subject_kind` | `user`, `group` | — |

**Platform permission vocabulary** (FR-PADM-1) — every element of `platform_role.permissions` must be in:
`rbac:read`, `rbac:write`, `node:enroll`, `node:quarantine`, `node:remove`, `ca:manage`, `ca:rotate`,
`request:approve`, `recording:replay`, `recording:export`, `audit:read`, `user:manage`, `settings:write`.

---

## 5. Structured selectors & sets

- **Selectors → `jsonb`.** `dp_rule.identity_selector`, `dp_rule.node_label_selector`,
  `dp_rule.source_ip_condition`, `jit_policy.target_selector`, `jit_policy.approval_chain`,
  `jit_request.approval_chain`/`approvals`, `access_lock.target_selector`, `join_token.scope`,
  `role_binding.scope`, and label maps (`node_policy.desired_labels`, `node.resolved_labels`) are `jsonb`.
  Each non-null selector carries `CHECK (jsonb_typeof(col) = 'object')` (or `'array'` for the chains). S5 owns
  evaluation; here we **store + round-trip + shape-validate**. Java type is **`com.fasterxml.jackson.databind.
  JsonNode`** via a converter to r2dbc-postgresql's `Json` wrapper (§9). JSONB round-trips *semantically*
  (Postgres canonicalises key order/whitespace), and `JsonNode.equals` is order-independent, so equality holds.
- **Approval-chain length 0–3** (FR-ACC-3): `CHECK (jsonb_typeof(approval_chain) = 'array' AND
  jsonb_array_length(approval_chain) <= 3)`. Length 0 is allowed (a Lock still fails closed at chain 0,
  FR-ACC-4).
- **Capability sets → `text[]` with a subset CHECK.** `CHECK (capabilities <@ ARRAY['shell','exec','sftp',
  'scp','port_forward_local','port_forward_remote','agent_forward','x11']::text[])` — the `<@`
  "contained-by" operator guarantees every element is a valid capability (an empty set trivially passes).
  **Why array over a child table:** capability sets are small, always read/written whole with their owning
  row, and never queried independently in this schema; an array keeps the row self-contained and avoids a
  join on the decision hot path. A GIN index makes the audit "search by capability" query (FR-AUD-8) fast
  without a child table. `principals` and `platform_role.permissions` are `text[]` for the same reasons
  (`permissions` also gets a subset CHECK against the permission vocabulary).

---

## 6. Snapshot-vs-FK — history must outlive config

**Decision (Design §6, §2.6):**
- **Within a class (runtime↔runtime, config↔config): real FKs.** e.g. `recording_ref.session_id → ssh_session`
  (1:1), `presence.node_id → node`, `agent_identity.node_id → node`, `role_binding.role_id → platform_role`.
- **Across runtime→config: never a hard FK — store a *snapshot*.** A `ssh_session`/`jit_request` references
  *what was decided* (a matched `dp_rule`, a `jit_policy`, a resolved principal, a capability set, a policy
  epoch) by copying the decision inputs/outputs onto the runtime row: `matched_rule_id uuid` (a **plain uuid,
  no FK**) + resolved `principal`, `capabilities`, `access_model`, `policy_epoch`, `grant_expiry`. Config rows
  are mutable and Git-reconcilable (edited/removed); audit and session history must stay complete and truthful
  **after** the producing config is gone.
- **Snapshot the config *name*, not just the id.** A dangling opaque UUID is not legible history. So every
  snapshot ref stores the human-readable name alongside the id: `ssh_session.matched_rule_name`,
  `jit_request.jit_policy_name`, `breakglass_activation.breakglass_policy_name` (mirroring the existing
  `node_name`/`gateway_name` snapshots). After a rule/policy is GC'd, an auditor can still see *which named
  rule/policy* authorized the access.
- **`audit_event` has *zero* FKs — it is immortal.** All its references (`correlation_id`, `session_id`,
  `subject`, `node_id`, `node_labels`) are plain values/snapshots, so no GC of any other table can orphan,
  block, or alter an audit row. Correlation across the SSH trail and the web/admin trail is **by id value**
  (FR-AUD-9); `node_labels` is a jsonb label snapshot so FR-AUD-8 "search by node/label" works over history
  even after a node is relabeled or removed. This is what "audit survives config GC" (doctrine §6) means.

Runtime→runtime FKs that could otherwise block history retention use `ON DELETE SET NULL` (e.g.
`ssh_session.node_id`, `ssh_session.gateway_id`, `ssh_session.jit_request_id`, `ssh_session.breakglass_activation_id`
— the last symmetric with `jit_request_id`, letting a break-glass review enumerate the sessions it authorized,
FR-ACC-6) alongside the name snapshots, so a hard delete of a node never destroys session history. The one
exception is **`recording_ref.session_id`, which is `ON DELETE RESTRICT`** (not CASCADE): a session prune must
not cascade-erase a recording's object key / encryption-key reference / hash-chain head (the crown jewels,
§15). A retention pruner must therefore be recording-aware.

---

## 7. Append-only audit, monotonic counters, write-once recording (in-DB, not by convention)

- **`audit_event` is append-only, enforced in the database** (Design §4.6): a `BEFORE UPDATE OR DELETE`
  (row) trigger and a `BEFORE TRUNCATE` (statement) trigger (`runtime.audit_event_immutable()`) `RAISE
  EXCEPTION`. **Scope of the guarantee (important):** the trigger stops the *honest / ORM / normal-DML* path —
  a stray `save()`-on-existing, a `deleteById`, a `TRUNCATE`. It does **not** stop a malicious or compromised
  holder of the app's DB role if that role *owns* the table (an owner can `ALTER TABLE … DISABLE TRIGGER` /
  `DROP`) or is a superuser (`SET session_replication_role = replica` silences origin triggers). Closing that
  requires the runtime to connect as a **non-owner, non-superuser role granted only `INSERT, SELECT`** on
  `runtime.audit_event`, plus reconciler-scoped schema grants for the config/runtime boundary — the S15/S16
  deployment-hardening layer. This session provides the structural boundary + the trigger; the role split is
  the documented follow-up. (Do **not** run the runtime as the table owner or as a superuser in production.)
- **Hash chain (S9): columns + a deterministic order.** `audit_event.prev_hash` / `record_hash` (row chain)
  and `recording_ref.hash_chain_head` (recording chain) are reserved. Because UUIDv7 is time-*ordered* but not
  a gapless total order (intra-ms ties; concurrent HA writers), `audit_event` also carries **`seq bigint
  GENERATED ALWAYS AS IDENTITY` (UNIQUE)** — a DB-assigned monotonic ordinal giving S9's chain a single
  well-defined predecessor and gap/fork detection. `seq` is DB-only (not mapped by the ORM, which omits it so
  Postgres assigns it). Adding this to the empty table now avoids a rewrite of the hottest table in S9.
- **Generation counter** (`agent_identity.generation`, `gateway_identity.generation`, Design §8.2) is an
  explicit `bigint` domain column with two guards: (1) the `@Version` optimistic lock (app) makes a stale
  renewal fail instead of racing; (2) a `BEFORE UPDATE` trigger (`runtime.enforce_generation_monotonic()`)
  rejects any *decrease* (DB). The guard is per-row: a fresh active identity for a re-provisioned node legally
  starts a new lineage at 0 (operator re-provision, FR-JOIN-5).
- **Presence ownership nonce is monotonic too.** `presence.nonce` (the anti-stale-ownership fencing token,
  §10.3/FR-HA-2) gets the identical `BEFORE UPDATE` guard (`runtime.enforce_presence_nonce_monotonic()`) so a
  stale/duplicated Gateway cannot re-claim a node by writing a lower nonce — a split-brain routing hazard the
  `@Version` lock alone would not catch.
- **Recording provenance is write-once.** A `BEFORE UPDATE` trigger on `recording_ref`
  (`runtime.enforce_recording_ref_write_once()`) rejects any change to `session_id` / `object_key` /
  `encryption_key_ref` (and to `hash_chain_head` once set), so recording metadata cannot be silently rewritten
  (evidence tampering, §15). Operational fields (`worm_mode`, `size_bytes`) stay mutable.
- **All triggers/functions are `CREATE OR REPLACE`** so a manual re-apply during a repair is idempotent (Flyway
  still runs each versioned migration exactly once).

---

## 8. Reserved SQL names — physical rename, Design names preserved

**Decision (Design §7.1, option b):** SQL-reserved/fragile conceptual names get **unambiguous physical
names**, with the Design name kept in a table comment and the R2DBC `@Table` mapping:

| Design §12A name | Physical table | Note |
|---|---|---|
| `session` | `runtime.ssh_session` | `session` is a reserved word; quoting it everywhere is a hazard across Flyway SQL / R2DBC / future hand-written queries. |
| `lock` | `runtime.access_lock` | `lock` is reserved/fragile; also the clearest place to encode "API-only". |

All other §12A names are safe and kept verbatim (`node`, `presence`, `pin`, `otp`, `dp_rule`, …).

---

## 9. R2DBC converters & mapping notes (for later sessions)

- **`jsonb` ↔ `JsonNode`:** two custom converters (`JsonNode → io.r2dbc.postgresql.codec.Json` writing,
  `Json → JsonNode` reading) registered in `R2dbcCustomConversions`. `r2dbc-postgresql` is therefore a
  **compile-scope** dependency (was runtime-only in S1) so the `Json` wrapper type is importable; it is still
  only the driver. Binding a bare `String` to a `jsonb` column fails (`text` ≠ `jsonb`); the `Json` wrapper is
  the correct bind type.
- **`text[]` ↔ `List<String>`:** native (r2dbc-postgresql `ArrayCodec`/`StringArrayCodec` + Spring Data array
  support). No converter. `List` (not `String[]`) so record `equals` is value-based.
- **`timestamptz` ↔ `Instant`:** native `InstantCodec`. No converter. Always UTC.
- **`uuid` ↔ `java.util.UUID`:** native `UuidCodec`.
- **IP / CIDR columns are `text` with a `CHECK (runtime.is_ip_or_cidr(col))` format guard** (`pin.source_cidr`,
  `otp.source_cidr`, `audit_event.source_ip`). **Driver limitation (documented deviation):** r2dbc-postgresql
  1.1.1 ships only `InetAddressCodec` (`inet` ↔ `java.net.InetAddress`, which *drops the prefix/mask*) and has
  **no `cidr` codec**. To store an IP/network *with its prefix* and round-trip it exactly over R2DBC we use
  `text` + a format-validating CHECK, and cast to `inet`/`cidr` at query time when S5/S6 need containment.
  `runtime.is_ip_or_cidr(text)` is a tiny `IMMUTABLE` plpgsql validator that wraps a **`::inet`** parse in an
  exception block and returns `false` on malformed input. Two design points: (1) it parses with `::inet`
  (lenient), not `::cidr` (strict), so operator-friendly forms with host bits set (e.g. `192.168.1.5/24`) are
  accepted rather than rejected — pushing callers to drop the restriction; (2) the exception wrapper turns bad
  input into a clean **CHECK (constraint) violation** (SQLSTATE 23, `DataIntegrityViolationException`) instead
  of a raw data/cast exception (SQLSTATE 22, `BadSqlGrammarException`), so callers see one uniform
  integrity-error type. A native `cidr`/`inet` column would require a custom `CodecRegistrar` — deferred to
  S5/S6, which own IP-containment logic. `dp_rule.source_ip_condition` is `jsonb` (a structured condition), not
  a cidr column, so it is unaffected.
- **Schema-qualified tables:** entities map with `@Table(schema = "config"|"runtime", name = "...")`; R2DBC
  emits schema-qualified SQL, so no `search_path` dependency.

---

## 10. Migration discipline (Design §14 — expand/contract, forward-only)

- Migrations are **additive and forward-only**. **Never edit a merged migration** (including the S1 no-op
  `V1__baseline.sql`); a change is always a *new* versioned file. One concern per file.
- Files (this session):
  - `V2__config_schema.sql` — `CREATE SCHEMA config` + the 9 config tables (enums, `origin`, config↔config FKs,
    reference-column content guards, CA rotation columns).
  - `V3__runtime_schema.sql` — `CREATE SCHEMA runtime` + the `is_ip_or_cidr` validator + the 13 runtime tables
    (runtime↔runtime FKs, the 1:1 `recording_ref` (RESTRICT), `presence`, generation counters, decision-snapshot
    columns incl. names, `audit_event.seq`, no runtime→config FKs).
  - `V4__triggers.sql` — `audit_event` append-only + generation-monotonic + presence-nonce-monotonic +
    recording-write-once triggers (all `CREATE OR REPLACE`).
  - `V5__indexes.sql` — query-pattern indexes (presence routing, audit search dims incl. GINs on `capabilities`
    and `node_labels`, live-session partial index, session lookup, FK columns, `audit_event.seq` UNIQUE, and the
    partial-unique "one active credential per node" / "one active CA config per kind").
- No `CREATE EXTENSION` is needed (UUIDs are app-side; `<@`, `jsonb`, GIN, IDENTITY are built-in).
- **Index migrations on populated tables (later sessions) must use `CREATE INDEX CONCURRENTLY`** (with Flyway
  transactional execution disabled for that file) to stay rolling-upgrade-safe (§14). V2–V5 are all-new tables,
  so plain `CREATE INDEX` here is fine.
- **Editing V2–V5 during this session was in-development** (they were never merged); once merged they are
  frozen and any change is a new `V6+`.

---

## 11. Config-vs-runtime table map (the authoritative list)

**CONFIG (`config` schema, Git-reconcilable, each row has `origin`):**

| Table | Purpose (Design §12A / FR) |
|---|---|
| `config.node_policy` | Desired labels, connector kind, declared host-pin / host-CA trust refs, stable policy key. |
| `config.dp_rule` | Data-plane grant: identity/node-label/source-IP selectors, principals, ttl, capability set, allow\|deny (FR-AUTHZ-1). |
| `config.platform_role` | Platform RBAC role = named set of granular permissions (FR-PADM-1). |
| `config.role_binding` | Binds a subject (user/group) to a `platform_role`, optionally scoped (FR-PADM-2). |
| `config.ca_config` | Per-CA (user/session/host) backend + **key reference** (never private material) + algorithm (FR-CA-1/4). A kind may have several rows during a rotation overlap (`rotation_state`); one is `active` (FR-CA-7). |
| `config.capability_def` | The requestable-capability catalogue. |
| `config.jit_policy` | What is JIT-requestable + the 0–3-level approval chain (FR-ACC-3). |
| `config.breakglass_policy` | Break-glass config: recording-strict, alert target, review requirement, auth path (FR-ACC-6). |
| `config.service_account` | Machine-consumer **definition** (issued creds are runtime) (FR-AUTH-12). |

**RUNTIME (`runtime` schema, never reconciled):**

| Table | Purpose (Design §12A / FR) |
|---|---|
| `runtime.node` | Live registration, resolved labels, health/status, owning-gateway pointer (FR-NODE-*). |
| `runtime.presence` | `node_id, owning_gateway, gateway_addr, nonce, nonce_id, last_seen` (Design §10.2, FR-HA-2). |
| `runtime.agent_identity` | Agent mTLS identity ref, `generation`, join method, status (Design §8, FR-JOIN-3). |
| `runtime.gateway_identity` | Gateway mTLS identity ref, `generation`, join method, status (FR-BOOT-3). |
| `runtime.join_token` | Token **hash** (never raw), scope, single-use, expiry, `consumed_at` (Design §8.1, FR-JOIN-2). |
| `runtime.ssh_session` | The `session` entity: identity, node, principal, gateway, access model, times + **decision snapshot** (FR-DATA-2). |
| `runtime.recording_ref` | 1:1 with `ssh_session`, object-store key, encryption-key **ref**, hash-chain head (FR-DATA-2, FR-AUD-3). |
| `runtime.access_lock` | The `lock` entity: target selector, mode, ttl, reason, created_by. **API-only** (FR-API-3). |
| `runtime.jit_request` | FR-ACC-2 state machine, requester, approver-chain progress, reason, two clocks. |
| `runtime.breakglass_activation` | Principal, reason, alert ref, review status (FR-ACC-6). |
| `runtime.pin` | Pubkey fingerprint, identity, source-cidr, principals, expiry (Design §5.5). |
| `runtime.otp` | OTP **hash** (never raw), identity, allowed principals, source-cidr, expiry, `used` (Design §5.4). |
| `runtime.audit_event` | Actor, subject, action, outcome, UTC time, correlation id. **Append-only, zero FKs** (§4.6, FR-AUD-9). |

---

## 12. Secrets-at-rest posture (Design §2.5, guardrails)

No raw secret is ever stored. `join_token.token_hash` and `otp.otp_hash` store **hashes**; `pin.fingerprint`
stores a **fingerprint**; `ca_config.key_reference`, `recording_ref.encryption_key_ref`,
`agent_identity.mtls_identity_ref`, `gateway_identity.mtls_identity_ref`, `service_account.key_reference`,
`node_policy.host_pin_ref`/`host_ca_ref` store **references**, never key material. Two layers of enforcement:
(1) tests assert structurally (via `information_schema`) that no `token`/`otp`/`secret`/`private_key` column
exists on those tables; (2) a belt-and-suspenders **content guard** `CHECK (col NOT LIKE '%PRIVATE KEY%' …)`
on the reference columns rejects a PEM private key that a later session might mistakenly try to write *into* a
correctly-named reference column (the structural test only checks column *names*). The hash/reference contract
itself — that the value really is a hash/reference — is enforced by the writing session's application code.
An issued service-account `client_secret` (if that auth method is used) is a **runtime** credential (a hash in
the `service_account_credential` table, added in S3 §13), never stored in the config definition.

---

## 13. Session Three additions (`V6`–`V12`) — CA signing + carry-forward remediation

S3 adds migrations `V6`–`V12` (forward-only; V2–V5 unchanged). New top-level tables: **12 config + 18 runtime =
30** (was 22), plus the `audit_event` range partitions.

### 13.1 Audit range partitioning + retention (`V7`, closes `F-audit-retention-1`)
`runtime.audit_event` is recreated as **`PARTITION BY RANGE (occurred_at)`** with **composite PK
`(id, occurred_at)`** (Postgres requires the partition key in every unique constraint). The V4 append-only
trigger, the `seq` identity, and the V5 indexes/GINs are re-established on the parent (row triggers + indexes
propagate to partitions). `uq_audit_seq` is `UNIQUE (seq, occurred_at)` — the single shared IDENTITY sequence
still makes `seq` globally unique (gap/fork detection for S9). A **DEFAULT** partition guarantees an append-only
insert never fails for a missing range. Management/prune functions (SECURITY DEFINER so the restricted runtime
role can call them without DDL rights): `audit_ensure_partition(date)` / `audit_ensure_partitions(date,int)`
(create-ahead, and lock each partition to INSERT/SELECT for `cp_runtime`), `audit_prune_before(timestamptz)`
(DETACH+DROP whole partitions older than the retention cutoff — no per-row DELETE, so retention never fights the
append-only trigger). Retention window = `operator_settings.audit_retention_days` (default 365, FR-AUD-6).

**R2DBC composite-PK mapping:** the entity keeps a single logical **`@Id id`** (globally unique by UUIDv7
construction) because `audit_event` is insert-only — `save()` inserts all columns including `occurred_at`, and
`findById(uuid)` resolves by `id` alone. No composite-key entity machinery is needed; the composite PK is purely
a partitioning/DB concern. Proven by `AuditPartitioningIT`.

### 13.2 Non-owner runtime DB role (`V11`, closes `F-append-only-1` residual)
`V11` creates a **non-owner, non-superuser `cp_runtime` role** (LOGIN password from the Flyway placeholder
`${cpRuntimePassword}`; dev default, override in prod). Grants: CRUD on `config.*` and `runtime.*` **except**
`runtime.audit_event` (INSERT/SELECT only — parent + every partition), EXECUTE on the helper functions, SELECT on
`flyway_schema_history`; **no** CREATE/ownership/ALTER/DROP/DISABLE TRIGGER. `ALTER DEFAULT PRIVILEGES` auto-grants
CRUD on future owner-created tables (audit partitions are re-locked to INSERT/SELECT by `audit_ensure_partition`).
**The R2DBC runtime connects as `cp_runtime`** (`spring.r2dbc.username`); **Flyway migrates as the owner**
(`spring.flyway.user`) — the S2 r2dbc-runtime / jdbc-flyway split. This makes the append-only + schema-boundary
guarantees hold against a compromised app credential, not just the honest/ORM path (which the V4 trigger covers).
Proven by `WriterRoleIT` (negative capabilities) and `AppendOnlyAuditIT` (trigger proven via an owner connection,
since `cp_runtime` is refused by privilege first). Credentials via env; nothing secret committed.

### 13.3 Model-gap schema (`V6`,`V8`,`V9`,`V10`,`V12`, closes `F-model-deferrals-1`)
- `config.operator_settings` (`V6`) — **singleton** (`singleton boolean UNIQUE CHECK`): KEK ref, default CA
  backend, retention/WORM/OTP/session-limit defaults, FR-BOOT-2 bootstrap self-disable flag. Cold start reads/writes
  it. The `bootstrap_*` fields are runtime-managed (the reconciler must not revert them, like `access_lock` is
  API-only).
- `recording_ref` (`V8`) — `retention_until`, `legal_hold`, `status`, `format`, `content_digest`; `content_digest`
  is write-once (V4 trigger extended); `recording_prunable(cutoff)` returns only governance + past-retention +
  non-legal-hold recordings (compliance/legal-held are never prunable).
- `runtime.service_account_credential` (`V9`, FR-AUTH-12) — issued machine creds (hash/reference only; snapshot ref
  to `config.service_account`).
- `runtime.device_flow` (`V9`, FR-AUTH-3) — RFC 8628 state; hashes of the device/user codes; `connection_binding`
  is the 1:1 anti-phishing binding (§15).
- `runtime.node_host_key` (`V9`, FR-CONN-5) — enrollment-anchored host identity (host-CA cert primary, pinned key
  fallback) so inner-leg verification is never TOFU; public material only.
- `runtime.session_lease` (`V9`, FR-SESS-3) — durable per-identity concurrency primitive (count of unreleased
  leases = live sessions; the semaphore is S7).
- `config.policy_epoch` (`V10`, F-DM-5) — singleton monotonic epoch (a decrease is trigger-rejected).
- `config.session_limit_policy` (`V10`, FR-SESS-3) — per-identity limit overrides.
- Status-transition **reason/actor** columns (`V10`) on `node`, `agent_identity`, `gateway_identity`, and
  `jit_request` (`decided_by`/`decision_reason`) so a quarantine/lock/decision is self-describing.
- `runtime.ca_key_material` (`V12`, FR-CA-8) — KEK-wrapped local CA private key (**ciphertext only**) + public
  material; the KEK is env-sourced, never in the DB, so a datastore-only compromise yields ciphertext it cannot
  unwrap. RUNTIME (generated secret, never reconciled); snapshot ref to `config.ca_config.key_reference =
  local:<id>`.

### 13.4 JIT `approvals` shape — a decision, not a defer (F-DM-16)
The `jit_request.approvals` chain stays **jsonb** (intentionally flexible; S11 fills the approval logic). Documented
element shape: `{approver, level, decision, reason, at}`. The self-approval invariant (approver ≠ requester,
FR-ACC-4) and the approver-queue index remain S11 concerns; keeping the shape as jsonb now is the deliberate choice
(a child table would over-commit before the logic exists).

### 13.5 CA-rotation uniqueness guard (`V13`, closes `R-ROT-2`)
`V13` adds a **partial unique index** so at most one `incoming` CA row can exist per `ca_kind` — without it, two
concurrent (or retried) `beginRotation` calls create two `incoming` rows and `promote` picks one arbitrarily,
stranding a never-expiring key in the trusted set. Forward-only; no table shape change.

## 14. Session Four additions (`V14`–`V15`) — internal mTLS plane + T4 hardening

S4 adds migrations `V14`–`V15` (forward-only; V2–V13 unchanged). New top-level tables: **12 config + 20 runtime =
32** (was 30), plus the `audit_event` range partitions. These carry the CP↔Gateway mTLS plane (VERSIONING.md §7,
Design §2A/§8/§15). No config table is added; the two new tables are both runtime.

### 14.1 Internal mTLS CA reuses the CA machinery (`V14`)
The internal mTLS CA is an **X.509 CA distinct from the three SSH CAs**, but it reuses the S3 CA lifecycle rather
than a parallel one:
- `config.ca_config.ca_kind` gains a fourth value **`'mtls'`** (expand/contract: the inline CHECK is dropped by
  its generated name and recreated as `('user','session','host','mtls')`; existing SSH-CA rows are untouched).
- `runtime.ca_key_material` gains a nullable **`ca_certificate bytea`** — the self-signed X.509 CA cert (DER),
  populated for the `mtls` CA (so the CP can serve `EnrollGatewayResponse.ca_chain` and reload the anchor) and
  **NULL** for SSH CAs (whose trust anchor is an OpenSSH public key, not an X.509 cert). The V12 write-once trigger
  is extended to cover `ca_certificate` alongside `wrapped_key`/`iv`/`public_key` — set once at insert, immortal
  after. The KEK-wrapped private key stays **ciphertext only**; the KEK is env-sourced (D2 key custody).

### 14.2 Single-use token tables (`V14`) — hash only, `@Version` consume
Two tables mirror the `join_token`/`otp` single-use shape (Design §8.1); both store the token **hash only** (the
raw token is never persisted) and gate the consume race with a `@Version` optimistic lock:
- **`runtime.gateway_enrollment_token`** (FR-JOIN-3 / Design §4.B) — the operator-provisioned bootstrap credential,
  scoped to one `gateway_name`, single-use (`consumed_at` set atomically on successful enroll), short TTL
  (`expires_at`, 10 min). This is the *only* credential that authenticates `GatewayIdentity.EnrollGateway`, which
  is reachable **without** a client certificate (the bootstrap exception, VERSIONING.md §7).
- **`runtime.session_signing_token`** (FR-CA-3 / Design §15) — the per-RPC session-bound authority for
  `SignSessionCertificate`, bound to `{gateway_id, session_id, node_id, principal, capabilities, exp}`. Single-use
  (`used`/`used_at`, atomic mark-used → replay is rejected), 120 s TTL. `capabilities` is CHECK-constrained to the
  SSH capability set; `source_address` is CIDR/IP-validated. S5/S8 will mint it from a real RBAC decision; S4 mints
  it via a minimal CP-internal path so the signing RPC is testable end-to-end.

### 14.3 T4 hardening (`V15`) — fingerprint pin + token-table least privilege
`V15` is forward-only and additive; it closes two T4 review findings:
- **M6 — client-cert fingerprint pin.** `runtime.gateway_identity` gains **`prev_fingerprint text`**. The
  `RenewGatewayIdentity` and `SignSessionCertificate` tiers pin the *presented* client cert's SHA-256 fingerprint
  to the stored `gateway_identity.fingerprint`, tolerating `{current, previous}` so the renew-ahead overlap still
  authenticates. `renew` records the outgoing fingerprint into `prev_fingerprint`; it is **NULL** for a
  freshly-enrolled (generation 0) identity. This makes `renew` an effective rotation/compromise-recovery primitive
  — a superseded certificate stops authenticating those tiers immediately, without waiting for the S10
  CRL/OCSP/lock-push fan-out. Public material.
- **L5 — token-table least privilege.** Both single-use token tables are consumed via an **UPDATE** (mark
  consumed/used), never a DELETE; `V15` **REVOKEs DELETE** on both from `cp_runtime` (V11's `ALTER DEFAULT
  PRIVILEGES` had auto-granted it), mirroring V12's write-once discipline. Runtime can create and consume a token
  but can never erase the single-use evidence.

## 15. Session Five (authorization) — **no schema change**

S5 builds the two authorization systems and the connect-time decision **entirely on the existing schema** —
no migration is added (the next free version stays **V16**). What S5 fills in is the *interpretation* of the
`jsonb` selectors S2 said it would only "store + round-trip + shape-validate" (§5), plus the runtime writes the
decision produces. The selector shapes below are the **contract the evaluator now enforces**; later sessions and
GitOps validation must stay aligned.

### 15.1 Data-plane RBAC selector shapes (`config.dp_rule`, read by the evaluator)
- **`identity_selector`** — `{"identities": [..], "groups": [..], "all": <bool>}`. Matches if the resolved
  identity is listed, any of its groups intersects `groups`, or `all` is true. An **absent/empty** identity
  selector selects **no one** (a grant must name a subject — fail safe).
- **`node_label_selector`** — `{ "<label-key>": <condition>, ... }` where a condition is
  `{"op": "eq"|"glob"|"in"|"regex", "value": "..", "values": [..]}` **or an array of conditions**. **AND across
  keys, OR within a key** (FR-AUTHZ-2). The `regex` operator is **anchored RE2/J** (linear-time, no ReDoS); a
  `null`/`{}` selector matches all nodes; a key the node lacks fails that key.
- **`source_ip_condition`** — `{"permit_cidrs": [..], "deny_cidrs": [..]}`. A pure **deny-only reducer**
  (FR-AUTH-15): a rule applies only if the source is inside `permit_cidrs` (when present) **and** outside every
  `deny_cidrs`. An unknown source with any restriction present **fails closed** (the grant is suppressed, never
  granted). Stored as `jsonb`, not a `cidr` column, so the driver's missing-`cidr`-codec limitation (§9) is moot;
  containment is computed in-process (`Cidrs`).

### 15.2 Lock target shape (`runtime.access_lock.target_selector`)
`{"identity": ".."}` / `{"node_id": ".."}` / `{"principal": ".."}` / `{"node_label": {"key":..,"value":..}}` —
a lock matches if **any** facet matches the connect. A Lock is the **top-tier un-overridable deny**; an empty or
uninterpretable target **matches** (a deliberate global-lockdown / typo-over-blocks-not-under-blocks — deny wins).

### 15.3 Platform RBAC scope shape (`config.role_binding.scope`)
`{"node_labels": {..}, "users": [..], "time": {"not_before": "<ISO>", "not_after": "<ISO>"}}` — a binding's scope
must **cover** a scopable request (`recording:replay/export`, FR-PADM-2): each present facet must be satisfied
(AND); an absent facet is unrestricted; a `null`/`{}` scope is an unrestricted binding. A **scoped** binding
cannot authorize an **unscoped/global** request.

### 15.4 Runtime writes the decision produces
- **`runtime.ssh_session`** — the decision snapshot is written on **allow** (`access_model='standing'`, the
  resolved `principal`, `capabilities`, `matched_rule_id`+`matched_rule_name`, `policy_epoch`, `grant_expiry`).
  The row's PK is the **Gateway-allocated `session_id`** so the decision context, the minted token, and the
  session history all correlate by one id.
- **`runtime.session_signing_token`** — now minted **from the real decision** (replacing S4's minimal path),
  bound to `{gateway_id, session_id, node_id, principal, capabilities, source_address, exp}`; minted **only on
  allow** (deny/lock → none, fail closed). ssh_session insert + allow audit + token mint are **one transaction**.
- **`runtime.audit_event`** — every data-plane decision (allow/deny/error) and every platform decision is
  recorded (FR-AUTHZ-5 / FR-PADM-3 / FR-AUD-7): generic outcome to the caller, specific reason (`matched_rule` /
  `LOCKED` / `NO_MATCHING_ALLOW` / …) in the log.

### 15.5 Decision-context signing key — **no table**
The connect-time context is signed by a dedicated **decision-context signer**: a fresh ECDSA P-256 keypair whose
public half is certified as a `CONTEXT_SIGNER` leaf (EKU codeSigning, URI SAN `sessionlayer://decision-context-signer`)
from the **internal mTLS CA** (`ca_kind='mtls'`). It is minted **in-memory, once per boot** (the Gateway pins the
CA, not the leaf — like the gRPC server cert), so **nothing is persisted** and no schema/migration is needed.

## 16. Session Six (authentication) additions — `V16`

S6 adds one forward-only migration, `V16__auth_surface.sql` (V2–V15 unchanged). New
top-level tables: **12 config + 23 runtime = 35** (was 32). Three new runtime tables
plus three columns on `runtime.device_flow`. No config table is added — the OIDC
provider (issuer/client/alg-allow-list/skew) is application config, and the first-admin
bootstrap reuses the existing `config.operator_settings.bootstrap_*` fields (V6).

### 16.1 New runtime tables (`V16`)
- **`runtime.oidc_login`** (FR-AUTH-6) — transient auth-code + PKCE relying-party state,
  one row per browser login, single-use (`consumed_at`). Stores the **SHA-256 of the
  opaque `state`** (`state_hash`, UNIQUE) as the lookup + single-use key; **the PKCE
  `code_verifier` and the OIDC `nonce` are NOT stored** — they are derived server-side
  (HMAC-SHA256 over the raw `state` under a per-boot key, `StateDerivation`) and recomputed
  at the callback. `purpose='device'` links the `device_flow` a login approves.
- **`runtime.auth_rate_limit`** (FR-AUTH-9) — durable fixed-window counters keyed by an
  opaque `bucket` (e.g. `otp:verify:<ip>`, `token:<clientId>`). One atomic upsert per
  event (`ON CONFLICT (bucket) DO UPDATE`); a request whose window count exceeds the
  limit is throttled. Durable across HA instances + restarts (unlike in-memory).
- **`runtime.consumed_assertion`** (FR-AUTH-12 / RFC 7523 §3) — single-use guard for
  `private_key_jwt` client-assertion `jti` (hash only, with the assertion's own
  `not_after`). `INSERT ... ON CONFLICT (jti_hash) DO NOTHING`; the first use wins,
  a replay loses. A periodic prune drops rows past `not_after`.

### 16.2 `device_flow` anti-phishing correlation (`V16` ALTER)
`runtime.device_flow` gains `approver_source_ip`, `approver_context jsonb`, and
`source_context_match boolean` (§5.2): the approving browser's source context, captured
at the CP verification page, correlated with the SSH source IP. Source IP is a **deny-only
reducer** (FR-AUTH-15) — a mismatch is flagged + audited, and denies only when
`sessionlayer.oidc.device.enforce-source-match` is set (default off).

### 16.3 Secrets-at-rest (Design §2.5) — unchanged posture, extended coverage
No raw secret is persisted anywhere this session: OTP → `otp_hash`; device/user codes →
`device_code_hash`/`user_code_hash`; auth-code `state` → `state_hash` (verifier/nonce
derived, never stored); machine `client_secret` → SHA-256; a `private_key_jwt` public key
→ base64 DER (public material) in `service_account_credential.secret_hash`; an mTLS
credential → the cert SHA-256 fingerprint; the printed-once bootstrap credential →
`operator_settings.bootstrap_credential_hash`. Constant-time compares (`Secrets`) on the
credential-verification paths. The machine-token and decision-context signing keys, and
the `StateDerivation` HMAC key, are per-boot in-memory (never persisted), like the S5
decision-context signer.

### 16.4 Runtime writes the auth surface produces
- `runtime.otp` — issued (hashed) by the admin OTP endpoint; consumed atomically by the
  Gateway (S7) via a single-use mark-used UPDATE.
- `runtime.pin` — created/revoked by the admin pin endpoints (TTL capped at
  `sessionlayer.authz.max-grant-ttl`); revocation by admin/offboarding/lock/back-channel.
- `runtime.service_account_credential` — issued/rotated/revoked by the admin machine-
  credential endpoints; revocation denies new tokens immediately.
- `runtime.device_flow` / `runtime.oidc_login` — begin/approve/poll of the device flow +
  the auth-code+PKCE RP.
- `runtime.audit_event` — every auth decision (login/otp/device/token/pin) and every admin
  mutation is recorded (FR-AUD-7): generic outcome, specific reason in the log.

## 17. Sessions Seven & Eight — **no schema change**

Neither the outer leg (S7) nor the inner leg (S8) adds a migration; the next free
version stays **V17**.

- **S7 (outer-leg auth)** implemented `OuterLegAuth` over the existing S6 tables
  (`otp`/`pin`/`service_account_credential`/`device_flow`/`oidc_login`).
- **S8 (inner leg)** added the `NodeConnection` field to `AuthorizeResponse`
  (additive proto, protocol stays 1.1) and *reads* existing inventory to fill it —
  `runtime.node` (`connector_kind`, `address` → dial address) and
  `runtime.node_host_key` (`source`, `public_key`, `host_cert_ref`) for the
  host-identity anchors (Design §9.3, FR-CONN-5/7), plus `CaRotationService`'s
  `host`-kind trusted CA keys. Public material only; no new tables/columns.

## 18. Session Nine (session recorder & WORM) additions — `V17`

Session Nine populates the reserved recording columns and adds the recording
metadata/policy surface (Design §12/§12A/§15; FR-AUD-1/2/3/6/9, FR-DATA-2). One
migration, `V17`; the next free version is **V18**.

### 18.1 Customer-key config on `config.operator_settings` (`V17`)

`operator_settings` gains the operator-configured **customer encryption key** and
recording policy. The CP holds the **public half only** (crown-jewels invariant,
§15) — a platform operator can never decrypt a recording:

- `recording_customer_public_key bytea` — DER SubjectPublicKeyInfo of the customer
  EC-P256 (ECIES) or RSA (RSA-OAEP) public key. **Nullable**; when NULL recording is
  un-provisioned and `BeginRecording` **fails closed** (keystroke capture is always
  on ⇒ encryption is mandatory, FR-AUD-2). Binary DER, so no reference/PEM guard.
- `recording_key_seal_algorithm text NOT NULL DEFAULT 'ecies_p256'` (CHECK
  `ecies_p256 | rsa_oaep_sha256`) — how the per-recording AES-256-GCM data key is
  sealed to the customer key. ECIES P-256 is the portable default.
- `recording_key_ref text` — the operator's opaque reference to the key, persisted
  into `recording_ref.encryption_key_ref` (never key material; the existing PEM
  content guard applies). Defaults to `customer-recording-key` at the service when
  unset so the NOT-NULL `encryption_key_ref` is always satisfiable.
- `recording_retention_days int NOT NULL DEFAULT 365` (`>= 1`) — the object-lock
  retain-until window + `recording_ref.retention_until` (FR-AUD-6). Floored at 1 (DB
  CHECK + app clamp) so a mis-set 0 can't yield a lock that expires immediately.
- `recording_strict_default boolean NOT NULL DEFAULT true` — reserved operator knob
  for future per-node recording-required policy; recording is mandatory + fail-closed
  in S9 regardless.

Adding columns to an existing table preserves its grants, so no re-grant is needed.

### 18.2 `runtime.recording_token` (`V17`) — the BeginRecording authority

The **second** single-use, session-bound token (mirroring `session_signing_token`),
minted at `Authorize` ALLOW alongside the signing token and bound to the same
`{gateway_id, session_id, node_id, principal, exp}`. It authorises exactly one
`Recording.BeginRecording` call, so a Gateway can never register a recording for a
session it does not broker (§15). Stores the token **hash** only; atomic single-use
via `used` under the `@Version` optimistic lock (replay loses the race). A **dedicated
table** (not a `purpose` column on `session_signing_token`) keeps the change additive
and isolated from the S5 signing-token entity/service. `V17` grants `cp_runtime`
SELECT/INSERT/UPDATE and REVOKEs DELETE (single-use ⇒ consumed by UPDATE, never
DELETEd — mirrors `V15`'s least-privilege on the token tables).

### 18.3 Recording columns now populated (write-once, `V3`/`V4`/`V8`)

`recording_ref` (the 1:1-with-session table) is now written by the CP:
`BeginRecording` inserts `object_key` / `encryption_key_ref` (customer-key ref) /
`worm_mode` / `retention_until` (status `recording`); `FinalizeRecording` fills
`hash_chain_head` / `content_digest` / `size_bytes` / `status`
(`finalized|truncated|failed`) — a NULL→value transition the `V4`/`V8` **write-once**
trigger permits once and then freezes (evidence tamper-evidence, §15). Ownership for
finalize is `recording_ref → ssh_session.gateway_id == caller` (no `gateway_id` column
added to `recording_ref`).

### 18.4 `audit_event` hash chain now populated (`V3` `seq`, S9 fills `prev_hash`/`record_hash`)

`AuditWriter` now links every audit write into the tamper-evidence chain:
`record_hash = SHA-256(prev_hash ‖ canonical(event))`, `prev_hash` = the previous
chained row's `record_hash` in `seq` order (`AuditRecordHash.GENESIS` for the first).
Because R2DBC inserts are concurrent (and HA runs multiple writers), each write
**serializes on a transaction-scoped advisory lock** (`pg_advisory_xact_lock`) inside
the audit transaction: take the lock, read the chain head, compute, insert (which
assigns the next `seq`). `canonical(event)` is a deterministic, length-framed encoding
of the semantic fields with `jsonb` keys sorted (invariant to Postgres key reordering)
and `occurred_at` truncated to microseconds (matching `timestamptz` resolution).
`AuditChainVerifier` recomputes the chain; a mutated or interior-removed/reordered row
breaks it (proven against the append-only table which cannot itself prove
content-integrity). The verifier also asserts `seq` is **strictly monotonic** (not
gapless — the IDENTITY sequence legitimately skips a value on a rolled-back insert). A
partial index `idx_audit_chain_head` on `(seq DESC) WHERE record_hash IS NOT NULL`
(V17) keeps the per-write chain-head read O(1); it is empty at creation (pre-S9 rows
have `record_hash` NULL) so the `CREATE INDEX` is instant even on a populated table.
**Tail-truncation resistance** (a DB superuser deleting the most recent rows, leaving a
shorter but still-consistent chain) is the SPEC-DEFERRED externally-anchored Merkle root
(FR-AUD-10 / D34) — hash-chain + WORM is the documented baseline, not a gap.

### 18.5 Recording bytes never touch the CP (Design §12.2)

The upload credential is issued **at upload time** by the separate `RequestUpload` RPC
(not at `BeginRecording`), so its life is the PUT, not the whole session — a
short-lived (default 120s), single-object **presigned PUT** (AWS SDK v2 `S3Presigner`)
to a WORM bucket created with **object-lock enabled**. The object-lock mode +
retain-until are baked into the **signature**, surfaced as `required_headers` the
Gateway must replay verbatim, so the uploader cannot strip the lock. No S3 network I/O
runs inside a DB transaction (bucket-ensure is eager at startup + idempotent; presign
is pure crypto). The Gateway uploads the **encrypted** bytes directly. WORM store config
is `sessionlayer.recording.worm.*` (not in the DB); the customer key + retention/mode
are operator settings above.

**Immutability against a compromised platform requires COMPLIANCE mode.** Governance
mode is deletable by a privileged, audited role (the GDPR erasure escape hatch), so the
"a compromised CP/admin can't alter a recording" (§15) guarantee holds strictly only
under compliance-mode object-lock; governance trades that for an operator-controlled
delete path.

## 19. Session Ten (per-channel re-eval & lock push) additions — `V18`

Session Ten adds the incident-response **lock CRUD** + the actively-pushed lock
deny-list (Design §6.3/§8.3/§8.4; FR-CHAN-3, FR-LOCK-1/2). One migration, `V18`; the
next free version is **V19**. It adds **no new table** — the lock is the existing
`runtime.access_lock` (`V3`, API-only, never reconciled).

### 19.1 `platform_role.permissions` CHECK widened (`V18`)

The lock CRUD is platform-RBAC gated by two new permissions, `lock:read` (list) and
`lock:write` (create/release). The `config.platform_role.permissions` column
CHECK-constrains the closed permission vocabulary (`V2`), so `V18` drops + recreates the
(anonymously-named) `platform_role_permissions_check` constraint with the two strings
added — mirroring the `V14` `ca_config_ca_kind_check` precedent. Existing roles remain a
subset of the widened set (no data change), and the S6 first-admin role (seeded from
`PlatformPermissions.ALL`) now carries the lock permissions automatically. No GRANT is
needed — `cp_runtime` already holds CRUD on `config.platform_role` (`V11`).

### 19.2 `access_lock.target_selector` canonical shape

The lock CRUD writes `target_selector` in the frozen `LockTarget` **plural** shape
(`identities` / `groups` / `node_ids` / `principals` / `node_labels` as `"key=value"` /
`all`), the exact facets the Gateway matches locally against the SIGNED decision context
(S5 `LockMatching`, ported to Rust). `LockMatching` recognises **both** this plural form
and the S5 **singular** back-compat form (`identity`/`group`/`node_id`/`principal`/
`node_label{key,value}`), OR-matched, so the connect-time deny path and the pushed
deny-list agree; an empty/unrecognised target still fails **closed** (matches — "deny
wins"). Ingest validation (`LockController`) rejects an empty/typo'd target up front and
requires an explicit `all:true` for a fleet-wide lock, so a global lockdown is never the
result of a typo.

### 19.3 Signed decision context gains identity / groups / node labels (no migration)

`DecisionContext` (the signed connect-time context, not a table) gains `identity`,
`identity_groups` and `node_labels` (sorted `"key=value"`), populated on the ALLOW path
from the resolved subject and the fixed node's inventory labels. They are **signed** so
the Gateway matches identity/group/label locks against trusted data on the per-channel
hot path — never data it was merely told. Additive; nothing is persisted (the context is
signed with the CA-anchored context-signer key, S5).

## 20. Session Twelve (Agent join & renewable identity) additions — `V19`

Session Twelve generalizes the Session-Four Gateway enrollment/renewal machinery for
per-node **Agents** (Design §8, FR-JOIN-1/3/4/6). The durable Agent credential is the
same renewable internal mTLS X.509 identity + generation counter the Gateway holds
(D25/D28), so the schema change is deliberately **symmetric with the gateway** and reuses
existing tables. One migration, `V19`; the next free version is **V20**.

### 20.1 `agent_identity.prev_fingerprint` (`V19`)

`runtime.agent_identity` (created `V3`) gains a nullable **`prev_fingerprint text`** — the
exact mirror of `V15`'s `gateway_identity.prev_fingerprint` (M6). At renew the CP pins the
presented client cert to **{current, prev}**, so a superseded (renewed-away) certificate
stops authenticating while the brief renew-ahead overlap is tolerated. `NULL` for a
freshly-enrolled (generation 0) identity; the previous generation's SHA-256 cert
fingerprint thereafter. Public material. `V19` also re-asserts the `cp_runtime` GRANTs on
`agent_identity`/`join_token` idempotently (already held from `V11`).

### 20.2 No new tables — the join methods reuse existing runtime entities

The three in-scope join methods and clone-detection add **no tables**:

- **`join_token`** (`V3`) backs `TokenJoin` — single-use, hash-only (the raw token is
  never stored), scope-bound; issuance/CRUD is the new `/v1/join-tokens` REST surface
  (platform-RBAC `node:enroll`, `V2`). `OidcJoin`/`MtlsJoin` are **tokenless** (a workload
  OIDC JWT verified against the issuer's JWKS; an operator-PKI cert + PoP) — verifier
  config lives in `sessionlayer.agent-join.*` application properties, not the DB.
- **`agent_identity`** (`V3`) holds the per-node mTLS identity ref + `generation` counter
  (§8.2) + `join_method` + `status`; one `active` per node (partial unique index, `V5`),
  and the `V4` monotonic-generation trigger already guards regressions.
- **`access_lock`** (`V3`, S10 push) is the clone-detection lock: a generation mismatch
  auto-locks by flipping `agent_identity.status='locked'` **and** inserting a strict,
  no-TTL `access_lock` covering the node (pushed to Gateways via the S10 `LockFeed`), plus
  a distinct `audit_event` alert (`agent.identity.clone_detected`). It **never
  auto-clears** — operator re-provision (§8.2). Revocation for every join method is via
  lock + generation counter, so no method is a standing bypass.

---

## 21. Session Thirteen (access models — JIT, break-glass & FIDO2) additions — `V20`

Session Thirteen wires the two elevated access models (Design §7, D15/D17;
FR-ACC-2..8). The JIT + break-glass **state** model was front-loaded in `V2`/`V3`
(`config.jit_policy`, `config.breakglass_policy`, `runtime.jit_request`,
`runtime.breakglass_activation`, and `ssh_session.access_model`/`jit_request_id`/
`breakglass_activation_id`), so S13 adds only the IdP-independent break-glass
**authentication** stores + one platform permission. One forward-only migration,
`V20`; the next free version is **V21**.

### 21.1 New runtime tables (`V20`)

- **`runtime.breakglass_credential`** — a registered break-glass FIDO2 `sk-ecdsa`
  **PUBLIC** key (the PRIMARY IdP-independent path, §5.2/§7). Mirrors `runtime.pin`:
  keyed by SHA-256 `key_fingerprint` (UNIQUE), holds the OpenSSH `sk-ecdsa` wire pubkey
  (`public_key bytea`, public material only), `sk_application` (audit legibility),
  `identity`, `allowed_principals` (a deny-only reducer on the requested login), an
  optional `node_selector` scope, optional `expires_at`, and `revoked_at`. No private
  key is ever at rest.
- **`runtime.breakglass_offline_code`** — a pre-issued single-use break-glass code (the
  IdP-independent FALLBACK, §7). Mirrors `runtime.otp`: `code_hash` only (UNIQUE; the
  raw code is never stored), ≥128-bit entropy, `identity` from the record (never client
  input), `allowed_principals`, optional `node_selector`/`source_cidr`, `expires_at`,
  atomic single-use via `used` under the `@Version` lock, and `revoked_at` for
  batch-invalidation without DELETE.
- **`runtime.breakglass_token`** — the single-use authority the CP mints on a successful
  break-glass RESOLVE and consumes at `Authorize` (§15). Mirrors `runtime.recording_token`:
  `token_hash` only, bound to `{gateway_id, identity, node_id, source_address, exp}` +
  the carried `allowed_principals`, atomic single-use. It ties a break-glass `Authorize`
  to a genuine credential resolution performed by THAT gateway — a Gateway can never
  assert break-glass without one.

### 21.2 `breakglass_activation` enrichment (`V20` ALTER)

`runtime.breakglass_activation` (created `V3`, with principal/reason/alert_ref/
review_status/reviewer + policy snapshot) gains **`identity`**, **`source_ip`**,
**`target_node_id`** (snapshot; no FK) and **`credential_ref`** so a post-hoc reviewer
sees the whole break-glass event (who, from where, against which node, with which
credential) without stitching from `audit_event` (FR-ACC-6, FR-AUD-7).

### 21.3 `platform_role.permissions` CHECK widened (`V20`)

The named `platform_role_permissions_check` is dropped + recreated (the `V18` pattern)
to admit **`breakglass:manage`** — the permission gating break-glass credential
registration (FIDO2 key add/revoke) and offline-code issuance. JIT approve/deny keeps
the existing `request:approve` (`V2`/`V18`); no other permission is added.

### 21.4 Grants + single-use posture

The three new runtime tables auto-inherit `cp_runtime` CRUD via `V11`'s
`ALTER DEFAULT PRIVILEGES`. Mirroring `V15`/`V17`, the **single-use** stores
(`breakglass_offline_code`, `breakglass_token`) `REVOKE DELETE` (a row is consumed by an
UPDATE, never DELETE); `breakglass_credential` keeps DELETE (an admin may remove a
registration outright, in addition to the soft `revoked_at`). No raw secret is stored:
FIDO2 keys are public, offline codes and the break-glass token are SHA-256 hashes;
source binding uses the shared `runtime.is_ip_or_cidr` guard + the lenient `::inet <<=`
deny-only reducer.

### 21.5 Access-model flow-through (no schema change)

JIT and break-glass reach the wire via the **existing** decision path. A JIT grant is
resolved server-side from an ACTIVE `jit_request` and fed to the S5 evaluator as a
time-boxed synthetic allow (so deny-overrides + the top-tier Lock still apply — a JIT
grant can never override an explicit deny or a Lock). Break-glass is the distinct
always-available path: `AuthorizeRequest.breakglass_token` (proto field 8) is consumed,
an activation + high-priority alert are raised **before** the decision, then the allow
is evaluated **subject to** the Lock (a locked target refuses break-glass while the
activation stands). `DecisionContext.access_model` (proto field 16, SIGNED, emitted only
when non-standing so standing decisions stay byte-identical) lets the Gateway force
strict recording for break-glass and pick the per-model mid-session-expiry behaviour.
JIT-revoke / break-glass-abort is expressed **as a `Lock`** (runtime), inheriting the
S10 fail-closed teardown — no new revocation entity.
