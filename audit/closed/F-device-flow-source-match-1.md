# F-device-flow-source-match-1: device-flow approver-IP↔SSH-IP binding is default-OFF (residual phishing relay)
- Severity: low
- Status: Accepted-Risk
- Area: oidc

## Context (S23 red-team panel A6, vs current OAuth device-flow guidance)

The CP-as-RP design (a full auth-code+PKCE relying party hosting its own verification
page, `DeviceFlowService`) structurally defeats the classic IdP-relay device-code
attack (the S6 anti-phishing core). The remaining residual — attacker starts the SSH
connection, socially-engineers a victim to approve the CP page — is mitigated by the
approver-IP↔SSH-source-IP correlation, but `OidcProperties.enforceSourceMatch` is
**false by default** (a mismatch is flagged + audited but only DENIES when enforcement
is enabled), and the soft /24 correlation can pass a same-subnet/NAT attacker.

## Why Accepted-Risk (documented §15 residual; NAT-safety keeps it opt-in)

Design §15 explicitly documents this as a residual for pen-test ("attacker-initiates,
victim-approves"), and device flow is **fallback-only** (primary is publickey via Vault
user cert / FIDO2), which bounds the blast radius. Enforcing exact source-IP match by
default would over-deny legitimate NAT/mobile approvers (the approving browser and the
SSH client are frequently on different networks — the design correlates IP/ASN/geo as
*evidence*, not an exact gate). The control (`enforceSourceMatch`) is available for
operators who accept that trade-off (e.g. a fixed-egress fleet).

**Operator recommendation (surfaced for the sign-off):** deployments that treat
device-flow phishing as in-scope should enable `enforceSourceMatch` and/or adopt IdP
number-matching. Number-matching as a first-class control is a candidate future
enhancement; it is a new feature, out of scope for this hardening pass.
