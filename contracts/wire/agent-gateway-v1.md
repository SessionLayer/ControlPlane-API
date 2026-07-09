# Agent ↔ Gateway Wire Protocol — v1 (specification)

**Status:** Session One skeleton specification. This is a **spec document, not
code.** Only the framing and version-negotiation preface are fixed here; the
message catalogue enumerates the types the design implies, with most marked
**reserved — defined in a later session**.

**Implements:** Design §9.2 (outbound-agent model), §10 (transport/HA),
FR-CONN-2, FR-HA-3/4/6/8, FR-HA-9 (explicit versioning + negotiation),
FR-JOIN-* (the credential lifecycle rides adjacent channels, not this data
preface).

> **Relationship to the CP↔Gateway gRPC contract.** The Agent↔Gateway path is a
> distinct protocol from the CP↔Gateway gRPC plane (`contracts/proto/`). It
> reuses the same `ProtocolVersion{major,minor}` *concept* and the same N-1
> compatibility policy (`contracts/VERSIONING.md`), but is a framed binary
> protocol over a mutually-authenticated transport (TLS/WebSocket), not gRPC.

---

## 1. Transport

- The **Agent dials out** to the Gateway (outbound-only; no inbound holes on the
  node — Design §9.2). Control connections are long-lived; the Agent holds **≥2
  control channels to failure-domain-diverse Gateways** and agents do **not**
  mesh (FR-HA-6).
- Session One does **not** implement the transport. The chosen carriage
  (WebSocket over TLS, per Design §1 "WebSocket for agents") and its mTLS
  identity (the renewable X.509 agent credential, Design §4/§8) are specified
  and built in later sessions (S12/S13).
- **No session plaintext and no session bytes ever traverse a coordination bus**
  (Design §10.2). Dial-back data rides a **direct** connection established from
  the address carried in the signal (FR-HA-4).

## 2. Framing

A minimal, self-describing binary framing (fixed this session so later sessions
share one parser):

```
+--------+--------+------------------+-----------------------------+
| VER(1) | TYPE(1)|   LENGTH(u32 BE) |     PAYLOAD (LENGTH bytes)   |
+--------+--------+------------------+-----------------------------+
```

- `VER` — the **negotiated** protocol major (see §3); a frame whose `VER` does
  not match the negotiated major is a protocol error → close.
- `TYPE` — message type (see §4).
- `LENGTH` — big-endian `u32` payload length. Implementations MUST enforce a
  configured maximum frame size and reject oversized frames (DoS guard).
- `PAYLOAD` — type-specific, length-delimited. Payload encoding (protobuf vs raw
  byte stream for spliced session data) is per message type.

Multiplexing of multiple logical channels over one control connection is
**reserved** (defined with the transport in S13).

## 3. Version negotiation (connection preface)

Immediately after the transport is established and before any other frame:

1. The Agent sends `HELLO` (`TYPE=0x01`) carrying its `ComponentInfo`
   (`name`, `semver`, `protocol_min`, `protocol_max`) — the same shape as
   `sessionlayer.controlplane.v1.ComponentInfo` in the gRPC contract.
2. The Gateway replies `HELLO_ACK` (`TYPE=0x02`) with its own `ComponentInfo`
   and the **selected** `ProtocolVersion` (highest common version, resolved
   exactly as in `VERSIONING.md` §3).
3. If no common version exists the Gateway sends `VERSION_REJECT`
   (`TYPE=0x03`) with both ranges and closes — **fail closed** (FR-HA-9).

All subsequent frames use the negotiated major in `VER`.

## 4. Message catalogue

| TYPE | Name | Direction | Session One status |
|---|---|---|---|
| `0x01` | `HELLO` | Agent → GW | **Specified** (preface) |
| `0x02` | `HELLO_ACK` | GW → Agent | **Specified** (preface) |
| `0x03` | `VERSION_REJECT` | GW → Agent | **Specified** (preface) |
| `0x10` | `PING` / `0x11` `PONG` | both | **Specified** (liveness, keep-alive) |
| `0x20` | `DIAL_BACK_REQUEST` | GW → Agent | Reserved — S13 (carries single-use signed dial-back token bound to `{node,session,gateway,principal,exp}`, FR-HA-8) |
| `0x21` | `DIAL_BACK_READY` | Agent → GW | Reserved — S13 |
| `0x30` | `STREAM_OPEN` | GW → Agent | Reserved — S13 (splice to `127.0.0.1:22`) |
| `0x31` | `STREAM_DATA` | both | Reserved — S13 (opaque inner-leg bytes; encrypted end-to-end at the SSH layer — the Agent never sees plaintext) |
| `0x32` | `STREAM_CLOSE` | both | Reserved — S13 |
| `0x40` | `NODE_STATUS` | Agent → GW | Reserved — S12 (labels + heartbeat, FR-NODE-2) |
| `0x50` | `CREDENTIAL_ROTATE` | both | Reserved — S12 (generation-counter renew signalling, FR-JOIN-4/5) |
| `0x7E` | `ERROR` | both | Reserved — typed error frame |
| `0x7F` | `GOAWAY` | both | Reserved — graceful drain (FR-HA-7) |

Type numbers are **stable**: once assigned they are never reused for a different
meaning (mirrors the protobuf field-number rule). Unknown reserved types received
in Session One MUST be rejected as protocol errors.

## 5. Security invariants (carried forward)

- The Agent runs **non-root** (FR-CONN-6); a compromised agent process cannot
  read the node host key.
- The Agent **never** sees SSH session plaintext — `STREAM_DATA` payloads are
  SSH-layer ciphertext bridged opaquely (Design §9.3 rationale).
- Dial-back tokens are **single-use and signed**, bound to
  `{node, session, gateway, principal, exp}` (FR-HA-8) — defined with `0x20`.
- Revocation is via **lock + generation counter** (Design §8.2/§8.4); no wire
  message is a standing bypass of a lock.
