# F-serial-allocator-1: no certificate serial allocator (KRL/audit) — Session-8 issuance concern
- Severity: low
- Status: Accepted-Risk
- Area: ca

## Summary
Divergence (F-caserial-1) + protocol (F-VALIDBEFORE-FOREVER-1) + divergence (F-caprofile-2): the
cert serial is caller-supplied (no unique/monotonic allocator), the assembler cannot express the
`valid before = uint64-max` "forever" sentinel (it derives validity from `Instant`), and the
inner-leg profile has no explicit TTL ceiling. Vault/step-ca/Teleport allocate unique serials and
clamp TTLs.

## Why Accepted-Risk (per §2.1 — genuinely a later-session capability)
These are all properties of **per-connection certificate issuance**, which is Session 8 — this
session builds and proves the signing *capability*, not the issuance *flow* (SESSION §1.2). Design
§10 also makes revocation = lock + short-TTL expiry (not KRL-by-serial), so a serial allocator is not
load-bearing for the baseline; and the delivered inner-leg profile is fixed-scope (~5-min TTL, backdated,
never "forever"), so the missing sentinel and TTL ceiling are unreachable in delivered scope. Adding an
unused serial allocator / sentinel / ceiling now would be speculative infrastructure ahead of its
consumer.

## Residual + follow-up (Session Eight)
When S8 wires issuance: allocate unique serials from a persistent monotonic source (keeps KRL-by-serial
open), add a max-TTL clamp to the profile, and add a "no-expiry" sentinel for long-lived host/CA certs.
Documented in RESULT §10.
