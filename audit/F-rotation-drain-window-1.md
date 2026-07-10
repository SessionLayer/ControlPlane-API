# F-rotation-drain-window-1: rotation promote/drain ordering has no enforced distribution gate
- Severity: medium
- Status: Accepted-Risk
- Area: ca

## Summary
Reliability (R-ROT-3) + divergence (F-carot-1) note that `CaRotationService` exposes
`promote` (incoming→active) and `drain` (outgoing→expired) with no enforced precondition:
`promote` before nodes trust the incoming key would reject the first cert signed by the new
CA, and `drain` before the outgoing key's certs/sessions expire would orphan them. Teleport
gates promotion on fleet-wide trust-acknowledgement and drain on a grace period ≥ max cert TTL.

## Why Accepted-Risk (not fixable this session, per §2.1)
The enforceable gate depends on the **node-facing trust distribution + acknowledgement signal**
(pushing `TrustedUserCAKeys` to nodes and confirming receipt), which is an **enrollment/Session-8**
capability — there is no fleet to distribute to or ack from yet. Enforcing a timing gate now would
be guessing at a signal that does not exist. What IS delivered and correct this session: the
overlap-then-drain state machine, the demote-then-promote ordering (never 0/2 active), the
trusted-set exposure (incoming+active+outgoing), and the incoming-uniqueness index
(F-cold-start-resilience-1). The ordering **invariant is documented** on `promote`/`drain` so S8
wiring cannot skip it.

## Residual + follow-up (Session Eight)
Gate `promote` on a distribution-confirmed signal and `drain` on `promoted_at + maxInnerLegTtl`
(needs a `promoted_at` column + the S8 distribution ack). Documented in RESULT §10 and DATA-MODEL.
