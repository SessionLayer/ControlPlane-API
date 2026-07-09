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

## 6. Current versions (Session One baseline)

| Contract | Version |
|---|---|
| CP ↔ Gateway gRPC `ProtocolVersion` | **1.0** (`protocol_min = protocol_max = 1.0`) |
| Agent ↔ Gateway wire `ProtocolVersion` | **1.0** |
| OpenAPI URI major | **v1** (spec `info.version: 0.1.0`) |

There is no prior release, so no N-1 peer exists yet; the window becomes
load-bearing from the first MINOR bump onward.
