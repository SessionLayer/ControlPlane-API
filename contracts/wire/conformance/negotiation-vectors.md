# Agent ↔ Gateway wire — version-negotiation conformance vectors

**Status:** starter conformance suite (Session Fourteen). Normative source:
`../agent-gateway-v1.md` §3. These vectors pin the **observable** negotiation
behaviour of any conformant endpoint to the frozen contract, so the
"both-sides-green-by-construction" class of drift (S14 `F-wireversion-1`) is
caught by each repo's **own** CI rather than only by a human cross-repo pass.

**How to consume (both repos):** vendor this file, then run each vector through
the endpoint's real advertisement + `resolve_common_version()` and assert the
outcome. No peer binary is needed — that is the point; it fits per-repo CI.

## The two obligations under test

- **O1 — advertisement conformance.** An endpoint MUST NOT advertise a wire
  `protocol_max` greater than the highest wire version it actually implements,
  and MUST NOT couple its advertised wire range to any *other* protocol's version
  (e.g. the CP↔Gateway gRPC plane). At the 1.0 baseline both advertised bounds
  MUST equal 1.0. **This is the assertion `F-wireversion-1` fails:** the Gateway
  advertised wire `1.1` by reusing the gRPC `PROTOCOL_MAX`.
- **O2 — resolution conformance.** Given two advertised ranges, the selected
  version is the highest common; if there is no overlap the Gateway sends
  `VERSION_REJECT` and closes (fail closed, no downgrade, no guess).

## O1 — advertised-range vectors

Each endpoint asserts, against **its own** advertisement, `advertised == expect`.

| # | endpoint | implements up to | conformant advertised range | note |
|---|---|---|---|---|
| A1 | Agent @ baseline | 1.0 | `[1.0, 1.0]` | |
| A2 | Gateway @ baseline | 1.0 | `[1.0, 1.0]` | **F-wireversion-1: MUST NOT be `[1.0,1.1]`** |
| A3 | either, gRPC plane at 1.7 | wire 1.0 | `[1.0, 1.0]` | wire range is independent of the gRPC version |

The load-bearing check is A3: it must hold **regardless** of the gRPC
`ProtocolVersion`, which is what forces a dedicated wire-version constant.

## O2 — resolution vectors

`resolve(agent_range, gateway_range) -> selected | REJECT`. Order-independent.

| # | agent range | gateway range | expect | rationale |
|---|---|---|---|---|
| R1 | `[1.0,1.0]` | `[1.0,1.0]` | `1.0` | baseline |
| R2 | `[1.0,1.0]` | `[1.0,1.1]` | `1.0` | N-1 window once wire 1.1 exists; a peer that only speaks 1.0 still interoperates. **Selecting 1.1 here is a bug** — the 1.0-only Agent has no 1.1 semantics |
| R3 | `[1.0,1.1]` | `[1.0,1.1]` | `1.1` | both implement 1.1 |
| R4 | `[1.1,1.1]` | `[1.0,1.0]` | `REJECT` | no overlap → `VERSION_REJECT`, fail closed |
| R5 | `[2.0,2.0]` | `[1.0,1.1]` | `REJECT` | major mismatch → fail closed; never stamp `VER=2` on a 1.x frame |

R2 is the one that would have caught `F-wireversion-1` end to end: with the
Gateway wrongly advertising `[1.0,1.1]`, R2's *selected* is still 1.0 (which is
why every existing test passed), so R2 alone is insufficient — **A2 is the vector
that fails on the real bug.** Both obligations are needed; O1 is the sharper one.

## Not yet included (S15)

- **Golden encoded frames.** Byte-exact frames + expected decode outcomes
  (oversized/short/trailing-garbage/unknown-type/text-frame-rejected) belong here
  too, but they must be **generated from a known-correct codec and cross-checked**,
  not hand-authored from prose — a subtly wrong golden frame is a worse oracle
  than none. Generate them in S15 from one repo's codec and have the other verify.
- **Pinned-released-peer smoke** and the **real HEAD-vs-HEAD Agent↔Gateway E2E**:
  see `RESULT.md` (Session Fourteen) — the latter needs cross-repo integration CI,
  which is S15 (HA) infrastructure.
