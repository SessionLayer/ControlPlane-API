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
