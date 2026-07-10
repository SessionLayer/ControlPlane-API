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
  no FK**) + resolved `principal`, `capabilities`, `access_model`, `policy_epoch`. Config rows are mutable and
  Git-reconcilable (edited/removed); audit and session history must stay complete and truthful **after** the
  producing config is gone.
- **`audit_event` has *zero* FKs — it is immortal.** All its references (`correlation_id`, `session_id`,
  `subject`, `node_id`) are plain values, so no GC of any other table can orphan, block, or alter an audit
  row. Correlation across the SSH trail and the web/admin trail is **by id value** (FR-AUD-9). This is what
  "audit survives config GC" (operating doctrine §6) means concretely.

Runtime→runtime FKs that could otherwise block history retention use `ON DELETE SET NULL` (e.g.
`ssh_session.node_id`, `ssh_session.gateway_id`, `ssh_session.jit_request_id`) alongside a denormalized name
snapshot (`node_name`, `gateway_name`), so a hard delete of a node never destroys session history.

---

## 7. Append-only audit & the generation counter (in-DB, not by convention)

- **`audit_event` is append-only, enforced in the database** (Design §4.6): a `BEFORE UPDATE OR DELETE`
  trigger (`runtime.audit_event_immutable()`) `RAISE EXCEPTION`s. Immutability therefore does not depend on
  application discipline or a writer role (a dedicated INSERT/SELECT-only writer role is the S15/S16
  deployment hardening layer on top; documented, not required for the guarantee here).
- **Hash-chain columns are reserved now** (S9): `audit_event.prev_hash` / `record_hash` (the row hash chain),
  and `recording_ref.hash_chain_head` (the recording hash-chain head). S9 fills them; the columns exist so no
  later migration has to rewrite the hottest table.
- **Generation counter** (`agent_identity.generation`, `gateway_identity.generation`, Design §8.2) is an
  explicit `bigint` domain column. Two guards: (1) the `@Version` optimistic lock (app layer) makes a stale
  renewal fail instead of racing; (2) a `BEFORE UPDATE` trigger
  (`runtime.enforce_generation_monotonic()`) rejects any update that *decreases* `generation` (DB layer).
  A cloned credential that forks the counter is thus detectable and the stale writer cannot regress it.

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
- **IP / CIDR columns are `text` with a `CHECK (runtime.is_cidr(col))` format guard** (`pin.source_cidr`,
  `otp.source_cidr`). **Driver limitation (documented deviation):** r2dbc-postgresql 1.1.1 ships only
  `InetAddressCodec` (`inet` ↔ `java.net.InetAddress`, which *drops the prefix/mask*) and has **no `cidr`
  codec**. To store a CIDR network *with its prefix* and round-trip it exactly over R2DBC we use `text` +
  a format-validating CHECK, and cast to `inet`/`cidr` at query time when S5/S6 need containment.
  `runtime.is_cidr(text)` is a tiny `IMMUTABLE` plpgsql validator that wraps the `::cidr` parse in an
  exception block and returns `false` on malformed input — so a bad CIDR raises a clean **CHECK (constraint)
  violation** (SQLSTATE 23, `DataIntegrityViolationException`) rather than a raw cast/data exception (SQLSTATE
  22, `BadSqlGrammarException`); application code then sees one uniform integrity-error type for all bad-data
  rejections. A native `cidr` column would require a custom `CodecRegistrar` — deferred, tracked for S5/S6.
  `dp_rule.source_ip_condition` is `jsonb` (a structured condition), not a cidr column, so it is unaffected.
- **Schema-qualified tables:** entities map with `@Table(schema = "config"|"runtime", name = "...")`; R2DBC
  emits schema-qualified SQL, so no `search_path` dependency.

---

## 10. Migration discipline (Design §14 — expand/contract, forward-only)

- Migrations are **additive and forward-only**. **Never edit a merged migration** (including the S1 no-op
  `V1__baseline.sql`); a change is always a *new* versioned file. One concern per file.
- Files (this session):
  - `V2__config_schema.sql` — `CREATE SCHEMA config` + the 9 config tables (enums, `origin`, config↔config FKs).
  - `V3__runtime_schema.sql` — `CREATE SCHEMA runtime` + the 13 runtime tables (runtime↔runtime FKs, the 1:1
    `recording_ref`, `presence`, generation counters, no runtime→config FKs).
  - `V4__triggers.sql` — the `audit_event` append-only trigger + the generation-monotonic trigger.
  - `V5__indexes.sql` — query-pattern indexes (presence routing, audit search dims incl. a GIN on
    `capabilities`, session lookup, FK columns, the partial-unique "one active credential per node").
- No `CREATE EXTENSION` is needed (UUIDs are app-side; `<@`, `jsonb`, GIN are built-in).

---

## 11. Config-vs-runtime table map (the authoritative list)

**CONFIG (`config` schema, Git-reconcilable, each row has `origin`):**

| Table | Purpose (Design §12A / FR) |
|---|---|
| `config.node_policy` | Desired labels, connector kind, declared host-pin / host-CA trust refs, stable policy key. |
| `config.dp_rule` | Data-plane grant: identity/node-label/source-IP selectors, principals, ttl, capability set, allow\|deny (FR-AUTHZ-1). |
| `config.platform_role` | Platform RBAC role = named set of granular permissions (FR-PADM-1). |
| `config.role_binding` | Binds a subject (user/group) to a `platform_role`, optionally scoped (FR-PADM-2). |
| `config.ca_config` | Per-CA (user/session/host) backend + **key reference** (never private material) + algorithm (FR-CA-1/4). |
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
`agent_identity.mtls_identity_ref`, `gateway_identity.mtls_identity_ref` store **references**, never key
material. Tests assert structurally (via `information_schema`) that no `token`/`otp`/`secret`/`private_key`
column exists on those tables.
</content>
</invoke>
