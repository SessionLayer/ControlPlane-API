# F-merkle-anchor-deferred-1: audit/recording tail-truncation has no external anchor (Merkle root deferred)
- Severity: medium
- Status: Accepted-Risk
- Area: audit

## Context (S23 red-team panel A6; Design D34 / FR-AUD-10)

The recording + audit hash-chains (`recorder/chain.rs`, `AuditChainVerifier`) detect
content mutation, reorder, and interior deletion, but the chain head is neither
producer-signed nor externally witnessed — so a DB **superuser** deleting the newest
rows leaves a shorter, still-consistent chain (undetectable). References (CT/Rekor
signed tree heads + gossip; Teleport continuous off-box SIEM) solve exactly this.

## Why Accepted-Risk — RATIFIED-DEFERRED (Design D34 / FR-AUD-10)

This is the spec-deferred externally-anchored Merkle root, decided this session as a
ratified deferral (see `Docs/sessions/twentythree/CARRYFORWARDS.md §B1`). The residual
is precisely bounded — tail-truncation of `audit_event` by a party who is a Postgres
superuser AND can delete the off-box-forwarded copy AND (for recordings) defeat
compliance-mode WORM object-lock — and is already mitigated in depth:
- **Recordings:** compliance-mode WORM object-lock makes finalized objects un-deletable
  for the retention window, and the S23 `F-recording-worm-version-1` version-pin binds
  replay/export to the finalized version — closing tail-truncation for recordings.
- **Audit:** the DB append-only trigger + the restricted `cp_runtime` role + immediate
  off-box forwarding (`AuditForwarder`, NFR-5) + the node-local `sshd` log (FR-AUD-4)
  are three independent stores an on-platform attacker does not jointly control.

The chain head is already computed + stored, so the anchor is additive (periodically
sign + publish the head to an external notary / transparency log) — the clean next
seam, not a gap. A6's incremental "signed off-box checkpoint" is recorded as the
lower-cost interim step toward the full external anchor.

**Operator precondition (sign-off):** regulated regimes needing non-repudiation beyond
immutability should enable compliance WORM + an off-box audit SIEM forward + a
restricted DB superuser, and track the external-anchor seam (Design §17).
