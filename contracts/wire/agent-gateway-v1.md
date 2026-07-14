# Agent ↔ Gateway Wire Protocol — v1 (specification)

**Status:** **FROZEN at protocol 1.0** (Session Fourteen). The Session-One
skeleton fixed the framing and the preface and reserved the rest; this revision
defines the reserved message types and the dial-back state machine, and is the
normative contract both implementations are built against.

**Payload encodings:** `contracts/proto/sessionlayer/agent/v1/wire.proto`.
**Implements:** Design §9.2 (outbound-agent model), §9.3 (host identity — which
holds over the splice), §10.2 (transport; the Agent dials out), §12.2 (node-local
second trail), D21/D22/D23/D24, D33; FR-CONN-1/2/3/6, FR-HA-4/8/9, FR-AUD-4.

> **Relationship to the CP↔Gateway gRPC contract.** This is a distinct protocol
> from the CP↔Gateway gRPC plane (`contracts/proto/sessionlayer/controlplane/`).
> It reuses the same `ProtocolVersion{major,minor}` concept, the same
> `ComponentInfo`, and the same N-1 compatibility policy
> (`contracts/VERSIONING.md`), but is a framed binary protocol over a
> mutually-authenticated WebSocket, not gRPC. **The Control Plane is not a party
> to it.**

---

## 1. Transport and connection roles

The **Agent dials out**; the Gateway never dials a node (Design §9.2). A node
needs **zero inbound reachability** — this is the whole point of the model.

Carriage is **WebSocket over TLS 1.3 with mutual TLS**
(`wss://`, Design §1 "WebSocket for agents"). There are exactly **two connection
roles**, distinguished by request path on one listener:

| Role | Path | Lifetime | Carries |
|---|---|---|---|
| **Control** | `/agent/v1/control` | Long-lived, one per Agent→Gateway pair | Preface, liveness, dial-back requests |
| **Dial-back** | `/agent/v1/dialback` | One per session, torn down with it | One session's opaque SSH bytes |

**Both roles present the same mTLS client certificate** — the Agent's renewable
X.509 identity (Design §4/§8; the S12 credential). Neither role is reachable
without it.

- **Agent → Gateway authentication.** The Gateway's TLS server **requires** a
  client certificate chaining to the **internal mTLS CA**, and resolves the peer
  from its SANs: URI SAN `sessionlayer://agent/<agent_id>` and dNSName SAN =
  the node's enrollment **name**. Both are stamped by the CP; neither is
  self-asserted. A certificate that does not resolve to exactly one agent is
  refused. The Gateway additionally refuses a peer covered by a **Lock** (the
  actively-pushed deny-list, §8.4/D26) — at registration **and** again at every
  dial-back. Deny wins.
- **Gateway → Agent authentication.** The Agent verifies the Gateway's TLS server
  certificate against the **same internal mTLS CA** it already holds (its
  `ca_chain`), with the Gateway's enrolled **name** as the expected server name.
  This leaf is a **serverAuth** certificate the Gateway obtains from
  `GatewayIdentity.IssueGatewayServerCertificate` — its clientAuth identity leaf
  is deliberately not usable here (one EKU per leaf). **There is no TOFU on this
  path either** (the platform trusts nothing on first use, anywhere).
- **No session plaintext, ever.** `STREAM_DATA` payloads are SSH-layer
  ciphertext. The Agent splices bytes it structurally cannot read (Design §9.3):
  the SSH session is end-to-end between the **Gateway** and the node's `sshd`.
- **No session bytes on a coordination bus** (Design §10.2). Dial-back data rides
  the direct connection the Agent opens to the address carried in the signal
  (FR-HA-4).

Multiplexing several sessions over one connection is **not** done and remains
unassigned: each session gets its own dial-back connection. This keeps bulk
session bytes off the control channel (no head-of-line blocking of a lock or a
heartbeat behind a file transfer) and makes a session's lifetime exactly a
connection's lifetime.

## 2. Framing

One frame per WebSocket **binary** message (a text message is a protocol error):

```
+--------+--------+------------------+------------------------------+
| VER(1) | TYPE(1)|   LENGTH(u32 BE) |     PAYLOAD (LENGTH bytes)   |
+--------+--------+------------------+------------------------------+
```

- `VER` — the **negotiated** protocol major (§3). A frame whose `VER` does not
  match is a protocol error → `ERROR` + close.
- `TYPE` — message type (§4).
- `LENGTH` — big-endian `u32`. Both peers MUST enforce `max_frame_bytes`
  (negotiated in `HELLO_ACK`) and reject an oversized frame **without
  buffering it** (DoS guard). `LENGTH` MUST equal the remaining message bytes;
  a short or trailing-garbage frame is a protocol error.
- `PAYLOAD` — for every type except `0x31`, the protobuf message named in §4.
  For `0x31 STREAM_DATA` the payload is **raw opaque bytes** (no protobuf): the
  session hot path pays no encoding cost, and the Agent has no decoder for what
  it carries.

## 3. Version negotiation (connection preface)

Immediately after the TLS handshake, before any other frame, on **both** roles:

1. Agent sends `HELLO` (`0x01`) with its `ComponentInfo`
   (`name`, `semver`, `protocol_min`, `protocol_max`).
2. Gateway replies `HELLO_ACK` (`0x02`) with its own `ComponentInfo`, the
   **selected** `ProtocolVersion` (highest common, resolved exactly as in
   `VERSIONING.md` §3), and the negotiated `heartbeat_interval_secs` +
   `max_frame_bytes`.
3. If no common version exists, the Gateway sends `VERSION_REJECT` (`0x03`) with
   its own range and closes — **fail closed** (FR-HA-9). The Agent MUST NOT
   retry with a guessed version.

The preface frames are sent with `VER = protocol_max.major` of the sender; every
subsequent frame carries the **negotiated** major.

**Baseline: protocol 1.0.** Both components ship `protocol_min = protocol_max =
1.0`, so the N-1 window is trivially satisfied today; it becomes load-bearing at
1.1.

## 4. Message catalogue

Type numbers are **stable**: once assigned, never reused for a different meaning
(the protobuf field-number rule). A type received in a role or state where it is
not legal is a protocol error.

| TYPE | Name | Direction | Role | Payload |
|---|---|---|---|---|
| `0x01` | `HELLO` | Agent → GW | both | `AgentHello` |
| `0x02` | `HELLO_ACK` | GW → Agent | both | `GatewayHelloAck` |
| `0x03` | `VERSION_REJECT` | GW → Agent | both | `VersionReject` |
| `0x10` | `PING` | either | control | `Ping` |
| `0x11` | `PONG` | either | control | `Pong` |
| `0x20` | `DIAL_BACK_REQUEST` | GW → Agent | control | `DialBackRequest` |
| `0x21` | `DIAL_BACK_RESULT` | Agent → GW | control | `DialBackResult` |
| `0x22` | `DIAL_BACK_AUTH` | Agent → GW | dial-back | `DialBackAuth` |
| `0x23` | `DIAL_BACK_ACCEPT` | GW → Agent | dial-back | `DialBackAccept` |
| `0x30` | `STREAM_OPEN` | Agent → GW | dial-back | `StreamOpen` |
| `0x31` | `STREAM_DATA` | either | dial-back | **raw bytes** |
| `0x32` | `STREAM_CLOSE` | either | dial-back | `StreamClose` |
| `0x7E` | `ERROR` | either | both | `WireError` |
| `0x40` | `NODE_STATUS` | Agent → GW | control | *reserved* — label/heartbeat reporting (FR-NODE-2) |
| `0x50` | `CREDENTIAL_ROTATE` | either | control | *reserved* |
| `0x7F` | `GOAWAY` | either | both | *reserved* — graceful drain (FR-HA-7) |

Reserved types MUST be rejected as protocol errors until they are defined.

**Renamed from the skeleton, same slot and direction:** `0x21` was pencilled in
as `DIAL_BACK_READY`; it is defined here as `DIAL_BACK_RESULT` because it must
also carry *failure* (a fast-fail so the Gateway need not wait out the dial-back
deadline to learn the node's `sshd` is down). **Re-directed:** `0x30 STREAM_OPEN`
was pencilled in as GW→Agent; it is Agent→GW, because only the Agent knows when
the loopback connection actually came up. Neither type was ever implemented in
its reserved form.

## 5. The dial-back state machine

```
  Gateway                                                   Agent
     |                                                        |
     |<==================== CONTROL (wss, mTLS) ==============|   registered, owns node N
     |                                                        |
  [session for node N authorized; connector_kind=OUTBOUND_AGENT]
     |                                                        |
     |  mint token T{jti,node,session,gw,principal,agent,exp} |
     |  pending[jti] = oneshot(ByteStream)                    |
     |-- 0x20 DIAL_BACK_REQUEST(T, endpoint, req_id) -------->|
     |                                                        |  node_name == mine?  (else REFUSED)
     |<- 0x21 DIAL_BACK_RESULT(req_id, accepted|error) -------|  fast-fail only; NOT readiness
     |                                                        |
     |<========= DIAL-BACK (wss, mTLS, new connection) =======|
     |<- 0x01 HELLO / 0x02 HELLO_ACK ------------------------>|
     |<- 0x22 DIAL_BACK_AUTH(T, req_id) ----------------------|
     |  verify T: sig, signer-fp, gw, exp, jti unused,        |
     |            mTLS peer == T.agent_id == owner(node)      |
     |  CONSUME jti (atomic remove)  ── replay now impossible |
     |-- 0x23 DIAL_BACK_ACCEPT ------------------------------>|
     |                                                        |  connect 127.0.0.1:22 (local config)
     |<- 0x30 STREAM_OPEN ------------------------------------|  splice live
     |                                                        |
     |  [ByteStream handed to the S8 inner leg — host verify, |
     |   inner cert, bridge, recorder: byte-for-byte the same |
     |   as agentless. The Agent is not a party to any of it.] |
     |<---------------- 0x31 STREAM_DATA (both) ------------->|
     |<---------------- 0x32 STREAM_CLOSE ------------------->|
```

**Timeouts, all fail-closed.** If the dial-back does not reach `STREAM_OPEN`
within `dial_back_timeout` (Gateway config), the Gateway abandons the pending
entry, drops the token, and the connector fails → the user sees the §7.1
post-authorization outcome **"target node is offline / unreachable"** (FR-SESS-5)
— exactly what an agentless dial to a dead node yields. A node with no registered
control channel fails the same way, immediately.

**The splice target is not on the wire.** The Agent connects to its own
locally-configured loopback address (`127.0.0.1:22` by default), which it
validates at startup to be a loopback address and refuses to start otherwise.
`DIAL_BACK_REQUEST` carries no target, so **no Gateway — however compromised —
can redirect an Agent's splice** or use it as a network pivot. This is the
confused-deputy defence and it is structural, not a check.

## 6. Dial-back token (FR-HA-8)

A **single-use, Gateway-signed capability** for exactly one dial-back.

```
SLDB1.<base64url(payload)>.<base64url(signature)>          (no padding)
```

- `payload` = `DialBackTokenPayload` (wire.proto), serialized.
- `signature` = ECDSA **P-256 / SHA-256** over
  `"sessionlayer-dialback-v1:" || payload_bytes` — domain-separated, so a
  signature can never be lifted from another context (mirrors the S10
  decision-context signer).
- **Verify-then-decode.** The verifier base64-decodes, checks the signature over
  **the transmitted bytes**, and only then parses them as protobuf. An unverified
  attacker-supplied buffer never reaches the decoder.

**Signing key.** A P-256 keypair generated per Gateway **process**, held in
memory, **never persisted**. `signer_key_fingerprint` (SHA-256 of its SPKI) is
inside the signed payload, so a token minted by a previous boot or a different
Gateway is refused before its signature is considered. Cross-Gateway verification
is never needed: a dial-back always terminates at the Gateway that issued the
token (whose address it carries).

**Accepted only if ALL hold** — any failure ⇒ `ERROR(UNAUTHORIZED)` + close, and
the specific reason goes to the operator log only:

1. Envelope well-formed, `SLDB1` prefix, signature valid under the current
   signing key, `signer_key_fingerprint` == this process's key.
2. `gateway_id` == this Gateway.
3. `issued_at - skew ≤ now < not_after`.
4. `jti` is **present in the pending map** — and removing it **is** consumption.
   A replay finds nothing and is refused. A token whose session already timed out
   finds nothing and is refused.
5. The dial-back connection's **mTLS identity** resolves to `agent_id`, **and**
   that agent is the owner of `node_name`. A token captured by a different Agent
   — even a valid, unlocked one — is worthless to it.
6. The pending entry's `{node_name, session_id, principal}` equal the payload's.
7. The agent is **not covered by a Lock** (re-checked here, not just at
   registration).

The token is **never logged, never persisted, and never echoed**. Only the `jti`
and its bindings are held (in memory, until consumed or expired) — so there is no
store of token material to steal.

## 7. Liveness, reconnect, and node availability

- The Gateway sends `PING` every `heartbeat_interval_secs`; the Agent answers
  `PONG` echoing the nonce. Two missed intervals ⇒ the peer is dead: the Gateway
  deregisters the agent (its node becomes unreachable) and the Agent reconnects.
- The Agent reconnects with **exponential backoff + jitter**, indefinitely. A
  reconnect re-runs the full TLS + mTLS + preface + registration path — there is
  no resumption and no cached authorization.
- **Re-registration replaces.** If an Agent registers for a node that already has
  a live control channel, the newer connection wins and the older is closed. A
  network partition must not lock a node out until a TCP timeout expires.
- **Credential rotation.** The Agent's identity is renewed by the renew-ahead
  loop (S12). The control channel observes the rotation and reconnects with the
  new certificate. The renew loop is **spawned, never awaited inline**: a
  terminal identity outcome stops *new* work and exits with its distinct code,
  but MUST NOT tear down live spliced sessions.
- **A node whose Agent is not connected is simply offline** (§7.1 / FR-SESS-5),
  reported post-authorization and specifically, exactly as for an unreachable
  agentless node.

## 8. Security invariants (normative)

- **The seam is invariant (D21/D23).** Everything above `NodeConnector` — inner
  cert, **no-TOFU host verification**, the byte bridge, the recorder — is
  byte-for-byte identical to the agentless path. The agent model changes only
  **how the Gateway obtains the `ByteStream`**. A compromised Agent cannot bypass
  host verification or the inner certificate: it does not hold, see, or influence
  either.
- **Host verification holds over the loopback splice** (§9.3). The Agent runs
  **non-root** (FR-CONN-6) and therefore cannot read the node's host key, so
  spoofing the node's host identity requires **node-root compromise** — the agent
  model raises that bar rather than lowering it. An Agent that spliced to an
  impostor would be caught by the Gateway's host-identity check, which aborts.
- **The Agent never sees plaintext, and never holds a session credential.** It
  splices ciphertext. The inner-leg private key never leaves the Gateway (D2).
- **Dial-back is authorized, bound, and single-use** (§6). Unauthenticated,
  replayed, expired, cross-session, cross-node, and cross-agent dial-backs are
  all refused, fail closed.
- **A Lock is honoured on this surface** (§8.4/D26): a locked agent identity
  cannot register and cannot redeem a dial-back. No wire message is a standing
  bypass of a lock, and revocation remains lock + generation counter (§8.2).
- **Non-disclosure holds here too** (§7.1): errors to an Agent are coarse
  (`PROTOCOL` / `UNAUTHORIZED` / `UNAVAILABLE`) and never reveal whether a node,
  session, or identity exists. Peer-supplied error text is untrusted: log it
  escaped; never interpolate it into an error chain that reaches a terminal
  print.
- **Node-local second trail (FR-AUD-4).** In the agent model the node's own
  `sshd` log is a **tamper-independent** second record of the session: the
  Gateway's inner certificate carries `key_id = session_id + identity`, and a
  node running `LogLevel VERBOSE` logs that key-id on every accepted
  certificate. The two trails cross-correlate on `session_id` with **no trust in
  the Agent** — which is what makes it independent.
