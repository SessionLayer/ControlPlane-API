# SessionLayer — Protocol & API Versioning Policy

This document is the authoritative statement of how the three cross-repo
contracts are versioned and how compatibility is maintained. It implements
**Design D33 / §16A** and **FR-HA-9**.

> **Why this matters.** SessionLayer components are released independently
> (OSS; mixed-version fleets are normal). A CP upgrade MUST NOT force a
> simultaneous fleet-wide Gateway/Agent upgrade. Versioning + negotiation is
> what makes independent release safe.

---

## 1. The three contracts

| Contract | Location | Versioning mechanism | Negotiated at runtime? |
|---|---|---|---|
| **CP ↔ Gateway gRPC** | `contracts/proto/` | `ProtocolVersion{major,minor}` exchanged via the `Handshake` service | **Yes** — `Handshake.Negotiate` at connect |
| **Agent ↔ Gateway wire** | `contracts/wire/` | `ProtocolVersion{major,minor}` in the connection preface | **Yes** — wire handshake at connect (spec: `wire/agent-gateway-v1.md`) |
| **REST / OpenAPI** | `contracts/openapi/` | URI path version (`/v1`) | No — client selects the URI major version |

All three share the same **`ProtocolVersion`** notion of `major.minor`
(defined once in `proto/.../common.proto` and mirrored by the wire preface and
the OpenAPI `ProtocolVersionRange` schema).

---

## 2. Semantics of a version number

`major.minor` (patch is deliberately **not** part of the protocol version — a
patch never changes the wire contract):

- **MAJOR** — an incompatible/breaking change (removed or renamed field, changed
  field number or semantics, removed RPC). Peers of different majors CANNOT
  interoperate; negotiation across a major gap fails closed.
- **MINOR** — a strictly **additive**, backward-compatible change within a major
  line (new optional field with a fresh field number, new RPC/message, new
  optional REST property). A newer minor speaking to an older minor within the
  window degrades to the older behaviour.

Protobuf field numbers are **never reused or renumbered**. Removed fields are
`reserved`. This is enforced mechanically by `buf breaking` in CI.

---

## 3. Version negotiation at connect

Both runtime protocols negotiate a common version before any application
traffic:

1. The initiator advertises its `[protocol_min, protocol_max]` range.
2. The responder computes the **highest common version**
   `v = min(client.max, server.max)` provided `v >= max(client.min, server.min)`.
3. If the interval is empty the peers share **no** common version → the
   responder **fails closed** (gRPC `FAILED_PRECONDITION` with a
   `NoCommonVersion` detail; the wire protocol sends a typed `VersionReject`
   frame and closes).

The resolution is a **pure function of the two ranges** — order-independent and
deterministic — so any CP/Gateway replica answers identically (matches the
determinism property the RBAC engine also relies on).

---

## 4. The N-1 compatibility window

The platform commits to an **N-1 window**: a component supports peers **one
minor version back** within the same major line. Concretely, a component at
minor `N` keeps `protocol_min` at `N-1`, so it can still talk to peers that have
not yet upgraded.

- Upgrading the CP from `1.N-1` to `1.N` does **not** require upgrading every
  Gateway/Agent the same day: a `1.N` CP still negotiates `1.(N-1)` with older
  peers.
- Breaking changes go through a **deprecate-then-remove** cycle spanning **at
  least one minor release**: a field/RPC is marked deprecated in release `1.N`,
  kept working through `1.(N+1)`, and only removed at a MAJOR bump.

## 5. Deprecation & removal procedure

1. **Add** the replacement (new field number / RPC / property) as a MINOR bump.
2. **Deprecate** the old element (protobuf `[deprecated = true]`, OpenAPI
   `deprecated: true`) — still fully functional. Announce in release notes.
3. **Keep** it working for at least one full minor release (the N-1 window).
4. **Remove** only at a MAJOR bump; the removed protobuf field number becomes
   `reserved`.

## 6. Current versions

| Contract | Version |
|---|---|
| CP ↔ Gateway gRPC `ProtocolVersion` | **1.1** (`protocol_min = 1.0`, `protocol_max = 1.1`) |
| Agent ↔ Gateway wire `ProtocolVersion` | **1.0** |
| OpenAPI URI major | **v1** (spec `info.version: 0.1.0`) |

**Session Four bumped the CP ↔ Gateway gRPC protocol from 1.0 to 1.1.** Session
Four added three additive services to the plane — `GatewayIdentity`
(`EnrollGateway`, `RenewGatewayIdentity`) and `SessionSigning`
(`SignSessionCertificate`) — carried over the new mTLS transport (§7). Adding an
RPC/message is, per §2, a **MINOR** change, so the honest advertised range moves
to `[1.0, 1.1]`. This is the **first MINOR bump**, so the N-1 window (§4) becomes
load-bearing now: a 1.1 CP keeps `protocol_min = 1.0` and still negotiates `1.0`
with a Gateway that has not upgraded (and vice-versa). The additions are
`buf breaking`-clean (adding files/services/messages is not a wire break); the
version number is the compatibility contract, not the wire-shape gate. The
protocol stays within **major 1**.

**Session Five added one more additive service — `Authorization` (`Authorize`)**
— the connect-time data-plane RBAC decision (FR-CHAN-1). Adding a service/messages
is additive and `buf breaking`-clean, and it fits within the existing **1.1**
minor (a new RPC within an already-bumped minor does not move the number again):
the advertised range stays `[1.0, 1.1]`, `protocol_min` stays 1.0, still within
major 1. `Authorize` returns a **signed** decision context: the signature is
ECDSA-P256/SHA-256 over `{"sessionlayer:decision-context:v1\n" || signed_context}`
where `signed_context` is the deterministic serialization of `DecisionContext`
(no maps → stable field-order encoding across Java/prost). The signer's leaf
certificate (returned in `signer_certificate`) chains to the internal mTLS CA the
Gateway already pins and carries the URI SAN `sessionlayer://decision-context-signer`,
so the Gateway verifies the context with no new trust distribution. Gateway-side
verification + caching + per-channel checks are **S10**; S5 is the CP producer.

**Session Seven added one more additive service — `OuterLegAuth`** — the
outer-leg **authentication** RPCs the Gateway calls to resolve an SSH credential
to a CP-owned identity: `ResolveUserCert`, `ResolvePin`, `ResolveOtp`,
`BeginDeviceFlow`, `PollDeviceFlow` (FR-AUTH-1..5, FR-AUTH-9/10). Adding a
service/messages is additive and `buf breaking`-clean, and it fits within the
existing **1.1** minor (a new RPC within an already-bumped minor does not move the
number again): the advertised range stays `[1.0, 1.1]`, `protocol_min` stays 1.0,
still within major 1. Every RPC is on the identity/session (mTLS-required) tier —
only an authenticated Gateway may resolve credentials. These RPCs authenticate
only (resolve credential → `{identity, principals}`); the Gateway still calls
`Authorization.Authorize` for the target node afterwards (invariant I2). Resolution
failure is **generic** (`resolved = false`, no reason) so the outer-leg auth
surface discloses no existence (§7.1). Source IP is a deny-only reducer throughout.

**Session Eight added one message field, not a service — `NodeConnection`** on
`AuthorizeResponse` (field 8, plus the `ConnectorKind` enum and the
`NodeConnection`/`HostVerification` messages). It tells the Gateway how to reach
the fixed node (connector kind + dial address) and how to verify the node's host
identity — host-CA trust keys + expected principals + the enrollment host cert(s),
or pinned host keys (Design §9; FR-CONN-1/2/5/7). Adding a field + messages + an
enum is additive and `buf breaking`-clean; it stays within **1.1** (a new field
within an already-bumped minor does not move the number): the advertised range
stays `[1.0, 1.1]`, `protocol_min` stays 1.0. `NodeConnection` is returned
**UNSIGNED** on the ALLOW path (unlike the signed decision context): it travels
over the authenticated, integrity-protected mTLS channel from the trusted CP, and
forging it requires compromising the CP itself (which already holds the
decision-context signing key), so a separate signature would add no security.

**Session Nine added one additive service — `Recording`** (`BeginRecording`,
`RequestUpload`, `FinalizeRecording`) — plus one field, `recording_token`
(field 9), on `AuthorizeResponse`. `RequestUpload` issues the short-lived,
single-object WORM upload credential at upload time (session end) rather than at
`BeginRecording`, so the credential's TTL need only cover the PUT — never the
whole session (§12.2; no long-lived upload creds). The service registers/finalizes a session recording and
issues short-lived, single-object WORM upload credentials (Design §12; FR-AUD-1/
2/3/9). `recording_token` is a second single-use token minted on ALLOW, bound to
the same `{gateway_id, session_id, node, principal, exp}` as `session_token`, that
authorises exactly one `BeginRecording` (session-bound authorization, §15).
Adding a service + messages + one field is additive and `buf breaking`-clean; it
stays within **1.1** (a new RPC/field within an already-bumped minor does not move
the number): the advertised range stays `[1.0, 1.1]`, `protocol_min` stays 1.0.
The `Recording` RPCs are on the identity/session (mTLS-required) tier;
`BeginRecording` additionally consumes the single-use `recording_token`. The
Gateway uploads the ENCRYPTED recording **directly** to the WORM store with the
issued credential — bytes never proxy through the CP (§12.2) — and the CP never
sees recording plaintext nor the per-recording data key (customer-held-key
sealing, FR-AUD-2).

**Session Ten added one additive service — `LockFeed`** (`StreamLocks`, the CP's
first **server-streaming** RPC — the actively-pushed lock deny-list, Design §6.3/
§8.3/§8.4; FR-CHAN-3, FR-LOCK-1/2) — plus three additive fields on
`DecisionContext`: `identity` (13), `identity_groups` (14), `node_labels` (15).
The new fields are SIGNED into the decision context so the Gateway matches
identity-/group-/label-targeted locks against trusted data locally, without a CP
round-trip on the per-channel hot path (FR-CHAN-2). Adding a service + messages +
three fields is additive and `buf breaking`-clean; it stays within **1.1** (a new
RPC/field within an already-bumped minor does not move the number): the advertised
range stays `[1.0, 1.1]`, `protocol_min` stays 1.0. `StreamLocks` is on the
gateway-identity (mTLS-required) tier; the whole fleet-wide lock set is delivered
to every Gateway (no per-Gateway filtering) and matching is a local Gateway
decision. The feed is the datastore-independent deny-list: a lock pushed once
keeps denying on every Gateway even under total datastore loss (the
asymmetric-degradation invariant). Lock CRUD is added as REST (`/v1/locks`,
platform-RBAC gated) — the **push** is gRPC; the **CRUD** is REST.

**Session Twelve added one additive service — `AgentIdentity`** (`EnrollAgent`,
`RenewAgentIdentity`, Design §8; FR-JOIN-1/3/4/6) — the CP↔Agent bootstrap +
renewable-mTLS-identity plane, plus the REST join-token API (`/v1/join-tokens`,
platform-RBAC `node:enroll`, FR-JOIN-2). It mirrors Session Four's
`GatewayIdentity`: the durable credential is ALWAYS a renewable internal mTLS
X.509 identity carrying a generation counter (§8.2), regardless of which
JoinMethod (`TokenJoinProof`/`OidcJoinProof`/`MtlsJoinProof`) bootstrapped it —
the deferred `BoundKeypairJoin` and further delegated methods (§17) drop in as
new `proof` oneof variants without a breaking change. Adding a service + messages
is additive and `buf breaking`-clean; it stays within **1.1** (a new RPC within
an already-bumped minor does not move the number): the advertised range stays
`[1.0, 1.1]`, `protocol_min` stays 1.0. `EnrollAgent` is on the bootstrap tier
(the join proof is the credential — the documented bootstrap exception, like
`EnrollGateway`); `RenewAgentIdentity` is on the mTLS-required (agent-identity)
tier. Revocation for every join method is via lock + generation counter (no join
method is a standing bypass). Join-token **issuance/CRUD is REST**; the
enroll/renew plane is **gRPC**.

**Session Thirteen added the access-models surface** (JIT + break-glass, Design §7,
D15/D17; FR-ACC-2..8) — additive, staying within **1.1**. Three changes, all
`buf breaking`-clean (new RPCs/messages/fields within an already-bumped minor do not
move the number): the advertised range stays `[1.0, 1.1]`, `protocol_min` stays 1.0.
1. **`OuterLegAuth` gained two RPCs** — `ResolveBreakglassKey` (a registered FIDO2
   `sk-ecdsa` PUBLIC key) and `ResolveBreakglassCode` (a pre-issued single-use offline
   code) — the **IdP-independent** break-glass authentication path (FIDO2 primary,
   offline codes fallback). Both are on the identity/session (mTLS-required) tier,
   authenticate only (resolve credential → `{identity, principals}` + a single-use
   `breakglass_token`), and fail generically (`resolved = false`, no token) so the
   surface discloses no existence (§7.1). The `code` is a secret (never logged).
2. **`AuthorizeRequest` gained `breakglass_token` (field 8).** Present only on a
   break-glass connect: the CP consumes it atomically, creates the
   `breakglass_activation`, fires the high-priority alert (on use), forces
   `access_model = BREAKGLASS` + strict recording, and evaluates a break-glass allow
   (the distinct always-available override of the standing dp_rule deny) **SUBJECT TO
   the top-tier Lock** — a matching Lock still denies (deny wins; a locked target
   refuses break-glass). JIT needs **no** request field: the CP resolves an ACTIVE
   `jit_request` grant for `{identity, node}` server-side and feeds it to the same
   evaluator as a time-boxed allow (subject to deny-overrides + Lock), so a JIT grant
   can never override an explicit deny or a Lock.
3. **`DecisionContext` gained `access_model` (field 16) + the `AccessModel` enum**
   (STANDING/JIT/BREAKGLASS), SIGNED into the context so the Gateway selects the
   per-model mid-session-expiry behaviour (FR-ACC-8/D17) and forces strict recording
   for break-glass against trusted data. An older (N-1) Gateway ignores the field and
   treats the decision as STANDING — the safe default. JIT/break-glass revocation is
   expressed **as a Lock** (runtime), inheriting the S10 fail-closed teardown — no new
   revocation RPC. The JIT/approval-chain/break-glass **admin CRUD is REST**
   (`/v1/jit-requests` + approve/deny/revoke, `/v1/breakglass/*`); only the break-glass
   **auth resolution** and the JIT/break-glass **grant flow-through** are gRPC.

**Session Fourteen froze the Agent ↔ Gateway wire protocol at 1.0** and added two
additive CP changes, both `buf breaking`-clean and staying within **1.1** (the
advertised gRPC range stays `[1.0, 1.1]`, `protocol_min` stays 1.0).

1. **The wire protocol itself** (`wire/agent-gateway-v1.md` + the messages-only
   `proto/sessionlayer/agent/v1/wire.proto`) is a **separate contract with its own
   version line**, negotiated in its own connection preface (§2 of this document
   already tracks it). The CP is **not a party** to it: it is Agent↔Gateway only,
   and lives here because `contracts/` is the canonical cross-repo home. Its
   baseline is **1.0** (`protocol_min = protocol_max = 1.0`), so the N-1 window is
   trivially satisfied today and becomes load-bearing at 1.1. Adding message types
   is additive; **type numbers are stable and never reused** (the field-number rule).
2. **`NodeConnection` gained `node_name` (field 4)** — the join key between an
   authorized session and the Agent that owns the node. The Gateway identifies a
   connected Agent from its mTLS certificate, whose dNSName SAN **the CP itself
   stamps from `node.name`**, so the CP must name the node in its connectivity
   answer. Required (non-empty) for `OUTBOUND_AGENT`; the Gateway fails closed to
   "node offline" without it. An older (N-1) Gateway ignores the field and simply
   has no agent path.
3. **`GatewayIdentity` gained `IssueGatewayServerCertificate`** — a **serverAuth**
   leaf for the Gateway's agent-facing TLS listener. The Enroll/Renew identity leaf
   is `clientAuth` (exactly one EKU per leaf, by design), so it cannot serve TLS: an
   Agent validating it as a server certificate would correctly reject it. Agents
   must verify a Gateway against an anchor they already hold — the same internal
   mTLS CA — rather than trust it on first use, so the Gateway needs a real
   serverAuth leaf. **The CP, not the caller, chooses the SANs** (stamped from the
   `gateway_identity` row), so a compromised Gateway cannot obtain a certificate for
   a name it does not own. It carries **no generation counter** — it is not an
   identity, it is a TLS credential derived from one; revocation is by locking the
   `gateway_identity` (the CP then refuses to reissue and the leaf expires).

**Session Fifteen (High Availability) added one additive CP service, four
additive `NodeConnection` fields, and a new Gateway↔Gateway contract**, all
`buf breaking`-clean and staying within **1.1** (the advertised gRPC range stays
`[1.0, 1.1]`, `protocol_min` stays 1.0). No migration (the `runtime.presence`
columns and `cp_runtime` grants were front-loaded in S2/S3).

1. **`Presence` service** (`proto/sessionlayer/controlplane/v1/presence.proto`) —
   `Heartbeat` (claim/refresh/standby with a monotonic nonce) and `Release`. The
   Gateway has no database access, so ownership of `runtime.presence` is written
   through the CP (Design D11: the CP is the sole Postgres owner), preserving the
   datastore boundary. The **owner is the authenticated mTLS peer** (`gateway_id`),
   never a request field. mTLS-required tier. Message names are package-unique
   (`PresenceHeartbeatRequest/Response`, not `Heartbeat` — that name is taken by
   `lock.proto`). An N-1 CP without the service simply cannot run HA; single-instance
   mode never calls it (the sole owner is always local).
2. **`NodeConnection` gained owner fields 5–8** (`owning_gateway_id`,
   `owning_gateway_addr`, `owner_nonce`, `owner_nonce_id`) — the routing READ path,
   folded into `Authorize` because the CP already does the authz round-trip there.
   Populated only when a **fresh** presence owner exists (agent nodes); empty ⇒ the
   Gateway fails closed to "node offline". UNSIGNED, like the rest of `NodeConnection`
   (it rides the trusted mTLS channel). An N-1 Gateway ignores the fields and has no
   HA routing (single-instance behaviour), so the window holds.
3. **A new Gateway↔Gateway contract** (`wire/gateway-relay-v1.md` +
   `proto/sessionlayer/gateway/v1/coordination.proto`) — the `CoordinationBackend`
   signal (`DialBackSignal`) and the direct peer-relay handshake
   (`RELAY_OPEN`/`ACCEPT`/`REJECT` = wire types `0x24`–`0x26`, additive to the shared
   registry) with the single-use **SLGW1** relay token. A **separate contract with
   its own 1.0 version line** (like the Agent↔Gateway wire); the CP is **not a party**
   (it lives here as the canonical cross-repo home; the CP generates unused Java).
   **Session bytes never traverse the coordination bus** — the bus is signalling only.

**Session Sixteen added host addressing + node lifecycle, all additive (gRPC stays
`1.1`, OpenAPI stays `v1`, wire stays `1.0`, no migration** — the node lifecycle
columns `node.status`/`health`/`status_*` and the `agent_identity` generation
guard were front-loaded in S2/S3/S10). `buf breaking`-clean vs `main`.

1. **`AuthorizeRequest.node_name` (field 9)** — the target node's HUMAN NAME the
   Gateway forwards from its `TargetResolver`. When set, the CP resolves it to
   `runtime.node.id` via `findByName` — **server-side + authoritative** (a
   client-asserted `node_id` is ignored when a name is present; §2.6/§11) — and an
   unknown name yields the same generic deny as any no-match (§7.1). Empty ⇒ the
   CP falls back to `node_id` (UUID) for direct-id callers. Closes
   `F-ha-connect-nodename-1`: the platform is usable by human node name across all
   three OpenSSH addressing modes. An N-1 CP without the field falls back to the
   `node_id` UUID (unchanged behaviour), so the window holds.
2. **A new additive service `HostCertSigning`** (`signing.proto`) —
   `SignGatewayHostCertificate` issues the Gateway's OUTER SSH host certificate
   (host CA) for the ProxyJump host-cert MITM path (§9.3/§11; FR-ADDR-1). Unlike
   `SessionSigning` it is NOT session-bound: it is authorized purely by the
   caller's ACTIVE, UNLOCKED gateway mTLS identity (the lock is the revocation).
   Key custody per D2 (Gateway sends only the public key; cert-only return). A new
   RPC within the already-bumped 1.1 minor does not move the number.
3. **OpenAPI `/v1/nodes`** — the `nodes` resource (register agentless / list / get
   / quarantine=S10-Lock / release / remove=deregister+revoke) + join-token
   issuance (S12, already present) so provisioning is an API flow, not hand-SQL
   (closes `F-ha-e2e-devseed-1`). Platform-RBAC gated
   (`node:enroll`/`node:quarantine`/`node:remove`) + audited. Adding paths/schemas
   is an additive, backward-compatible OpenAPI change within URI major **v1**.

**Session Seventeen completed + FROZE the OpenAPI surface — additive OpenAPI only
(gRPC stays `1.1`, wire stays `1.0`, URI major stays `v1`, `info.version` stays
`0.1.0`).** No protobuf/wire change, so `buf breaking` is untouched. Two migrations
(`V21`, `V22`) — neither is a contract-version event.

1. **Full config-resource CRUD** — `rules`, `roles`, `role-bindings`, `cas`
   (+ `rotate`), `service-accounts`, `node-policies`, `capability-defs`,
   `jit-policies`, `breakglass-policies` — plus runtime `sessions` (list/get/
   terminate). Adding paths/schemas/tags is additive within URI major **v1**;
   controllers implement the **generated** interfaces (the drift gate). Each is
   platform-RBAC gated + audited, invalid config rejected pre-commit (`422`,
   FR-API-5). `cas` NEVER exposes private key material.
2. **The API conventions (FR-API-1)** are realised across the new surface: cursor
   (keyset) pagination on collections (`cursor`/`limit` params + `*Page` envelopes
   with `nextCursor`), an `Idempotency-Key` header on mutating operations (retry-safe
   replay; a same-key-different-body reuse is a `422`), and RFC 9457
   `application/problem+json` errors with stable `type` URIs.
3. **The COMPLETE-CONTRACT FREEZE.** `recordings` (list/get + replay/export
   signed-URL) and `audit-events` (search/get) are authored now as the **frozen
   contract** and return `501` until **Session 18** implements the behaviour behind
   them. After this session the OpenAPI contract is **complete**, so the Dashboard
   (Session 19) can be built in parallel against a finalized typed client.
4. **`origin` provenance** narrowed (`V21`): the config `origin` CHECK is tightened
   to `IN ('api','ui','default')` — external config automation was descoped (owner
   decision); config is UI + API over Postgres (D11). The column and the config/
   runtime schema split are retained.

**Session Eighteen implemented the frozen audit/recording read side — additive
OpenAPI only (gRPC stays `1.1`, wire stays `1.0`, URI major stays `v1`,
`info.version` stays `0.1.0`).** No protobuf/wire change, so `buf breaking` is
untouched. One migration (`V23`) — not a contract-version event. The `recordings`
and `audit-events` operations moved from `501` stub to implemented; the drift gate
(controllers implement the generated interfaces) stays green.

1. **Audit-event search / get** (`/v1/audit-events`, FR-AUD-8/9) — implemented.
   To cover every FR-AUD-8 dimension the search gained **additive optional query
   params** (`capability`, `accessModel`, `nodeLabel` repeatable, `correlationId`)
   on top of the frozen set. Adding optional query params is backward-compatible
   within URI major **v1**. `audit:read`-gated, results RBAC-scope-filtered,
   read-only (the append-only hash chain stays verifiable).
2. **Recording replay/export** (`/v1/recordings/{id}/replay|export`, FR-AUD-5) —
   implemented as short-lived signed **GET** URLs to the still-encrypted object
   (bytes never through the CP; the CP cannot decrypt). `recording:replay`/
   `recording:export`-gated, scopable (FR-PADM-2), itself audited.
3. **Recording retention/legal-hold/governance-delete** (FR-AUD-3/6) — two
   **additive** operations: `DELETE /v1/recordings/{id}` (governance erasure) and
   `PUT /v1/recordings/{id}/legal-hold`, both gated on the **new**
   `recording:delete` platform permission (added additively to the
   `PlatformPermission` enum + the `platform_role` CHECK, `V23`). `RecordingResource`
   gained additive optional fields (`identity`, `nodeId`, `status`, `wormMode`,
   `prunedAt`). Compliance-mode = un-deletable (object-lock); legal hold blocks
   both prune and governance delete.

**Session Twenty-Five completed FR-SESS-3 enforcement — all additive (gRPC stays
`1.1`, wire stays `1.0`, URI major stays `v1`, `info.version` stays `0.1.0`).**
`buf breaking`-clean vs `main` (one new context field, two new RPCs within the
already-bumped 1.1 minor — neither moves the number).

1. **`DecisionContext.idle_timeout_seconds` (field 17)** — the resolved
   per-identity idle timeout, SIGNED into the decision context so it reaches the
   Gateway on trusted data (never client-suppliable). The Gateway applies it
   TIGHTEN-ONLY against its static `max_session_idle_secs` (the smaller wins).
   `0`/absent ⇒ no per-identity idle policy. An N-1 Gateway ignores the field
   and keeps its static idle bound — safe (the CP-side max-duration ceiling,
   folded into `grant_expiry`, still holds). The per-identity **max session
   duration** needed NO wire change: the CP folds
   `min(policy.max_session_seconds, grant TTL)` into the existing
   `grant_expiry_epoch_seconds`, which the S13/FR-ACC-8 expiry machinery already
   enforces.
2. **Two additive `Authorization` RPCs** (a new RPC within the already-bumped
   1.1 minor does not move the number):
   - **`NotifySessionEnd`** — the Gateway's reliable session-end signal: releases
     the FR-SESS-3 concurrency lease (and stamps the session ended) promptly on
     EVERY teardown path, including the degraded ones where no recording exists
     and `Recording.FinalizeRecording` never fires. Idempotent; caller-bound to
     the session's brokering gateway (mTLS identity, never a request field) — a
     Gateway can never free another Gateway's slot. Lifecycle-only: the S8/S9
     byte-bridge and recording seams are unchanged.
   - **`ExtendSessionLease`** — exact-accounting support for `RunToTtl`: a live
     session outliving `grant_expiry` still occupies its concurrency slot; the
     Gateway re-stamps the lease ahead of expiry. The extension window is
     server-authoritative (no duration on the wire). Caller-bound like
     `NotifySessionEnd`.
   An N-1 CP without these RPCs returns `UNIMPLEMENTED`; the Gateway treats that
   as best-effort (the lease then self-heals via the reaper exactly as in S24),
   so the window holds.
3. **OpenAPI `/v1/session-limit-policies`** — the FR-SESS-3 write surface
   (`config.session_limit_policy` CRUD) following the S17 conventions: cursor
   pagination, `Idempotency-Key`, RFC 9457, version-required optimistic
   concurrency, pre-commit selector/limit validation (`422`), `origin='api'`.
   Reads `rbac:read`; writes `settings:write` + audited. Adding paths/schemas/a
   tag is additive within URI major **v1**.

---

## 7. CP ↔ Gateway mTLS trust model (Session Four)

The CP ↔ Gateway gRPC plane runs over **TLS 1.3, mutually authenticated**,
replacing the Session-One dev-plaintext localhost channel. This section is the
authoritative statement of the trust model the two repos implement against.

- **Trust anchor.** A CP-operated **internal mTLS CA** (X.509, ECDSA P-256,
  distinct from the three SSH CAs) is the single trust anchor for the plane. The
  CP presents a **server certificate** issued by it; the Gateway presents a
  **client certificate** issued by it. Each peer verifies the other's chain
  against the internal CA, checks validity, and checks the SAN. No other trust
  anchor is accepted; plaintext and non-CA certs are refused (fail closed,
  NFR-2). TLS 1.3 only.

- **Bootstrap exception (the one asymmetry).** A Gateway that has not yet
  enrolled holds no CP-issued client certificate. `GatewayIdentity.EnrollGateway`
  is therefore reachable over the same TLS transport **without** a client
  certificate and is authenticated by a **single-use enrollment token** instead;
  `Handshake.Negotiate` (which carries no secrets) is likewise reachable pre-mTLS
  so a peer can resolve a common version at connect. **Every other RPC** —
  `RenewGatewayIdentity` and `SignSessionCertificate` — **requires** a valid
  client certificate chained to the internal CA that resolves to an active,
  unlocked `gateway_identity`. Enforcement is per-RPC (a server interceptor
  independently re-validates the peer chain), so the requirement never depends on
  a single TLS-layer toggle.

- **Layered per-RPC authorization (Design §15).** mTLS authenticates the
  *channel* (which Gateway). `SignSessionCertificate` additionally requires a
  single-use, CP-minted **session token** bound to
  `{gateway_id, session_id, node, principal, exp}`; the token authorizes the
  specific request. A Gateway can never obtain a certificate for a session it
  does not own. **Session Five** makes `Authorization.Authorize` the producer of
  that token: it is on the same identity/session-required tier (a valid client
  cert resolving to an active, unlocked `gateway_identity`), and it mints the
  token **only on ALLOW**, bound to the AUTHENTICATED caller's gateway id (never a
  request field) plus `{session, node, principal, capabilities, source_address,
  exp}`. A DENY or a matching Lock mints nothing (fail closed).

- **Key custody (D2).** Gateways generate their own keypairs (mTLS identity and
  inner-leg) and send only a CSR / public key. The CP returns certificates only
  and never receives or stores a Gateway private key.

- **Versioning interaction.** Version negotiation (`Handshake.Negotiate`) now
  runs over the secured channel. A version mismatch fails closed with gRPC
  `FAILED_PRECONDITION` exactly as before (§3); it is independent of the mTLS
  outcome (a peer that fails mTLS never reaches negotiation on the mTLS-required
  RPCs).
