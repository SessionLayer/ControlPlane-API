# Gateway ↔ Gateway HA Relay & Coordination — v1 (specification)

**Status:** **FROZEN at protocol 1.0** (Session Fifteen). Introduced with the
High-Availability work. Reuses the Agent↔Gateway framing, preface and
`ProtocolVersion` negotiation verbatim; it is a distinct *profile* of the same
framed binary transport, exchanged **Gateway-to-Gateway**.

**Payload encodings:** `contracts/proto/sessionlayer/gateway/v1/coordination.proto`.
**Implements:** Design §10.2 (three mechanisms, no overlap), §10.3 (routing,
failure, migration); FR-HA-3/4/5/8, NFR-1, NFR-2.

> **The Control Plane is not a party to this protocol.** The CP owns presence
> (the READ folds into `Authorization.Authorize`; the WRITE is
> `controlplane/v1/Presence`), but the coordination signal and the byte relay are
> Gateway-to-Gateway.

---

## 0. The three mechanisms (no overlap — Design §10.2)

| Mechanism | Carries | Transport |
|---|---|---|
| Postgres presence | durable ownership (`node → owner, addr, monotonic nonce`) | CP gRPC (`Presence` + `Authorize`) |
| `CoordinationBackend` | **signalling only** — one `DialBackSignal` to the owner | NATS (ref) / in-process (single mode) |
| Direct relay | **the node byte stream** | direct on-demand Gateway↔Gateway WSS+mTLS |

**Anti-requirement (normative):** session bytes MUST NEVER traverse the
CoordinationBackend. The bus carries only the `DialBackSignal`. Proven by test:
the bus sees no session plaintext or ciphertext.

---

## 1. Roles and the end-to-end flow

- **Ingress** gw-A holds the client's SSH connection, owns the session + recording,
  and runs the inner leg. It is the RELAY **server**.
- **Owner** gw-B currently holds the target node's agent control channel (per
  presence). It produces the node byte stream (its own local S14 agent dial-back)
  and is the RELAY **client** — it dials back to the ingress, mirroring the agent
  dial-back model (the party that can reach the resource dials the party holding
  the client).

```
client --ssh--> gw-A (ingress)
                  | Authorize -> ALLOW + NodeConnection{owning_gateway_id=gw-B, owner_nonce=N}
                  | mint SLGW1 relay token; publish DialBackSignal(addr=gw-A, token) via CoordinationBackend
                  v
                gw-B (owner) receives signal on sl.dialback.gw-B
                  | verify it still owns node (registry + nonce N)
                  | LOCAL S14 agent dial-back -> node ByteStream
                  | dial gw-A peer-relay endpoint (wss+mTLS), RELAY_OPEN(token)
                  v
gw-A <==== direct relay (STREAM_DATA raw bytes) ====> gw-B <--splice--> node:22
  | inner leg + host-verify + bridge + RECORDER (all at gw-A, unchanged)
```

The client is **never redirected**. gw-B runs **no inner leg and no recorder** —
it is a dumb byte relay.

---

## 2. Transport and connection role

Carriage is **WebSocket over TLS 1.3 with mutual TLS** (`wss://`), on the ingress's
peer-relay listener (the same TLS server that terminates agent connections; the
internal mTLS CA is the trust anchor). One connection **role**:

- **`/peer/v1/relay`** — a per-session byte relay. The connecting peer (owner)
  presents its **gateway-identity** client certificate (URI SAN
  `sessionlayer://gateway/<id>`), distinguishing it from an agent connection
  (`sessionlayer://agent/<id>`). The ingress binds the connection to the token's
  `owner_gateway_id` and MUST reject a peer whose authenticated id differs.

## 3. Framing and negotiation

Identical to Agent↔Gateway v1 §2–§3: `VER(1)|TYPE(1)|LENGTH(u32 BE)|PAYLOAD`, one
frame per WebSocket binary message, `STREAM_DATA` payload is raw opaque bytes.
The preface is the same `HELLO`/`HELLO_ACK`/`VERSION_REJECT` exchange resolving a
common `ProtocolVersion` (this profile is **1.0**), fail-closed on no common
version. `max_frame_bytes` MUST exceed the inner `max_packet`.

## 4. Message catalogue (additive to the shared TYPE registry)

| TYPE | Name | Direction | Payload |
|---|---|---|---|
| `0x01` | `HELLO` | either | `AgentHello` (reused as the generic hello) |
| `0x02` | `HELLO_ACK` | ingress → owner | `GatewayHelloAck` |
| `0x03` | `VERSION_REJECT` | ingress → owner | `VersionReject` |
| `0x24` | `RELAY_OPEN` | owner → ingress | `RelayOpen` — the SLGW1 token |
| `0x25` | `RELAY_ACCEPT` | ingress → owner | `RelayAccept` — bytes may flow |
| `0x26` | `RELAY_REJECT` | ingress → owner | `RelayReject` — code; then close (fail closed) |
| `0x31` | `STREAM_DATA` | either | **raw bytes** — the node stream |
| `0x32` | `STREAM_CLOSE` | either | `StreamClose` — per-direction half-close |
| `0x7E` | `ERROR` | either | `WireError` |

`0x24`–`0x26` were free slots in the shared registry; adding them is additive and
does not move the wire version. The relay never uses the agent-only dial-back
types (`0x20`–`0x23`, `0x30`).

## 5. The relay handshake state machine

```
owner (client)                                   ingress (server, /peer/v1/relay)
   |-- TLS 1.3 mTLS (gateway-identity cert) ------------->|  verify vs internal CA; peer id := SAN
   |-- 0x01 HELLO ------------------------------------->  |
   |<- 0x02 HELLO_ACK (selected=1.0, bounds) ----------  |
   |-- 0x24 RELAY_OPEN(token=SLGW1...) ---------------->  |  verify-then-decode; check bindings + single-use
   |<- 0x25 RELAY_ACCEPT ------------------------------  |  bind conn to session; hand ByteStream to inner leg
   |<--------------- 0x31 STREAM_DATA (both) ---------->  |
   |<--------------- 0x32 STREAM_CLOSE (per dir) ------>  |
```

On any binding failure the ingress sends `0x26 RELAY_REJECT(code)` and closes; the
owner tears down its local splice. A relay that is not accepted within the
ingress's bounded `relay_timeout` is abandoned and the SSH handshake fails closed
(a hung peer never hangs the handshake — FR-HA-5).

## 6. The relay token — SLGW1 (FR-HA-8, normative)

`SLGW1.<b64url(payload)>.<b64url(sig)>`, ECDSA **P-256 / SHA-256** over
`"sessionlayer-gw-relay-v1\0" || payload_bytes`. **Verify-then-decode**: the
signature is checked over the transmitted payload bytes *before* the protobuf
(`RelayTokenPayload`) is parsed.

- **Minted and verified by the ingress** with a **per-process** P-256 key (never
  persisted; `signer_fingerprint` in the payload rejects a token from another boot
  or Gateway) — the exact SLDB1 pattern.
- **Single-use**: consumed from an in-memory pending ledger keyed by `jti`;
  removal *is* consumption. A replay finds nothing.
- **Bindings, all required** (else `RELAY_REJECT`, fail closed): unexpired
  (`exp_epoch_ms`); `signer_fingerprint` == this ingress's key; the authenticated
  mTLS peer id == `owner_gateway_id`; `session_id`/`node_id`/`node_name` match the
  awaiting session; `owner_nonce` still current (the ingress bound the nonce it saw
  at `Authorize`). Cross-owner / cross-session / cross-node / expired / stale-nonce
  are all refused.
- **Never logged, persisted, or echoed.**

## 7. Security invariants (normative)

1. **Bytes never on the bus** (§0). The relay is direct; the bus is signalling only.
2. **The ingress owns the session and the recording.** gw-B relays raw bytes; all
   recording, host-verify, inner-leg and lock enforcement happen at gw-A exactly as
   in the single-instance path (S9/S10 unchanged).
3. **Fail closed on routing ambiguity** (FR-HA-5): no fresh owner / stale nonce /
   unreachable owner / relay not established within `relay_timeout` → deny within
   the bound. The monotonic nonce is the anti-stale-ownership primitive.
4. **The owner authenticates as a Gateway** (internal-CA `sessionlayer://gateway/<id>`
   cert) and MUST equal the token's `owner_gateway_id`. A compromised or
   superseded peer cannot serve a relay for a node it does not own.
5. **No live migration** (FR-HA-7): a relay is per-session; a lost owner fails the
   session fast (client reconnects, cheap via pinned-key silent reconnect).
