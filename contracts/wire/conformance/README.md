# Wire conformance vectors

Machine-checkable vectors that pin the **observable wire behaviour** of the
Agent↔Gateway (`agent-gateway-v1.md`) and Gateway↔Gateway relay
(`gateway-relay-v1.md`) protocols, so each consumer repo's **own** CI catches
cross-repo drift instead of relying on a human pass (the S14 `F-wireversion-1`
class of bug).

Two files, two obligations:

| File | Pins | Consumed by |
|---|---|---|
| `negotiation-vectors.md` | version **negotiation** (advertised range + `resolve_common_version`) | each repo's version logic |
| `frames.json` | byte-exact **frame encodings** + decoder rejection behaviour | each repo's wire codec |

Both are **vendored** into the Gateway and Agent repos (like the protos) and run
in their `gate` job. No peer binary is needed — that is the point.

## `frames.json`

Golden frames, **generated from a known-correct codec, never hand-authored** (a
subtly wrong golden frame is a worse oracle than none). Framing is the frozen
`VER(1) | TYPE(1) | LENGTH(u32 BE) | PAYLOAD`; payloads are the prost
serialization of the message named in the catalogue (§4), except `STREAM_DATA`
whose payload is raw opaque bytes. The prost encoding is deterministic over the
same frozen proto both repos generate from, so the bytes are authoritative; the
generator additionally decodes every frame it emits (self-check) and asserts a
hand-computable anchor (`Ping{nonce=42}` → `011000000002082a`).

Regenerate **only when the contract changes**:

```
cd framegen && cargo run          # rewrites ../frames.json ; commit the diff
```

`framegen/` is a self-contained dev tool (its own `target/`, prost over the vendored
protos) so regenerating never touches a consumer repo's build.

### What each repo asserts (portable, no field-construction glue)

For every entry in `frames`:

1. **Decode** `frame_hex` with the repo's codec → succeeds, and the decoded
   `ver` / `type` / `payload` equal `ver` / `type` / `payload_hex`.
2. **Re-frame** `encode(ver, type, payload)` → equals `frame_hex` byte-for-byte.

Together these pin the framing *and* the exact payload bytes both sides must
agree on, without needing to reconstruct each message from its fields. A repo
that additionally wants to pin *semantic* construction can build the message from
`fields` + `message` and assert its `encode_to_vec()` equals `payload_hex` — the
Gateway does this for the types it owns.

For every entry in `decode_negatives`: **decode** `hex` → the codec rejects it
with the error named by `expect` (mapping to `agent/wire.rs::FrameError`:
`Short` / `LengthMismatch` / `TooLarge` / `UnknownType` / `BadVersion`). The
oversized case is rejected **at the length header, without buffering the body**.

A reference consumer test (portable Rust, drop into each repo's `tests/`) lives
in [`consumer-test.rs.txt`](./consumer-test.rs.txt).

## How the cross-repo wire tests run (the two tiers)

The wire is proven at two tiers, split so the cheap deterministic checks live in
every repo's own CI and the expensive real-binary run stays out of it:

**Tier 1 — per-repo conformance (this directory).** `frames.json` +
`negotiation-vectors.md` are vendored into the Gateway and Agent repos (via each
`scripts/sync-contracts.sh`, alongside the protos) and run in each repo's `gate`
job as `tests/wire_conformance.rs` (from `consumer-test.rs.txt`). No peer binary,
no network, no Docker — a repo catches its **own** wire/codec drift (the S14
`F-wireversion-1` class) before it ever reaches a cross-repo run. Same golden
bytes on both sides is the mechanically-enforced contract.

**Tier 2 — cross-repo real-two-binary E2E (`scripts/ha-e2e.sh`).** The HA relay
path can only be proven with real binaries talking to each other, so it is **not**
part of any per-repo CI — a repo's CI checks out that repo alone and has no
sibling binary. It is a parent-level orchestration invoked with `make ha-e2e`: a
real CP jar + two real Gateways (gw-A ingress / gw-B owner) + a real Agent +
Postgres + NATS + target-sshd + an ssh client, asserting the command runs across
the gw-A→gw-B relay, the ingress owns the recording, no session bytes touch the
coordination bus (§0 anti-requirement), and NFR-1 (kill the owner) re-routes a new
session instead of hanging. It needs all three binaries, so it runs on demand for
release evidence (RESULT), not on push; `preflight()` exits BLOCKED (3) with no
side effects until `GW_A_CMD` / `GW_B_CMD` / `AGENT_CMD` are supplied.

The parent `SessionLayer/` folder is intentionally not a git repo, so
`scripts/ha-e2e.sh` and the parent `Makefile` are not version-controlled — **this
file is the durable record** of how the cross-repo run is wired and what it
proves.
