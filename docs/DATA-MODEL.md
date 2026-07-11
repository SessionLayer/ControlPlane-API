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
