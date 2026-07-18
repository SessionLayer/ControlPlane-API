# F-agent-forward-cert-1: inner-leg cert mapped agent_forward→permit-agent-forwarding though agent forwarding is always refused
- Severity: low
- Status: Verified-Fixed
- Area: ca

## Context (S23 red-team panel A5)

FR-SESS-2 requires agent forwarding to be **always refused**; the Gateway enforces
this unconditionally (`handler.rs::agent_request → Ok(false)`, incl. the ProxyJump
inner hop). But `CertificateProfiles.extensionsFor` still mapped a granted
`agent_forward` capability to the `permit-agent-forwarding` OpenSSH cert extension.
Not exploitable today (the outer-leg refusal is unconditional), but the defense was
single-layered: if RBAC ever granted `agent_forward`, the node-facing inner cert
would *tell the node to permit* agent forwarding, leaving only the Gateway refusal
between that and forwarding to the node.

## Root-cause fix

Drop the `agent_forward → permit-agent-forwarding` mapping from
`CertificateProfiles.extensionsFor` — the inner cert never carries
`permit-agent-forwarding` regardless of the granted capability set. Now two
independent controls uphold FR-SESS-2 (the cert doesn't permit it AND the Gateway
refuses it).

## Regression test

`CertificateProfilesTest.grantedAgentForwardNeverYieldsPermitAgentForwarding` —
`extensionsFor({shell, agent_forward, x11})` contains `permit-pty` +
`permit-X11-forwarding` but NOT `permit-agent-forwarding`.
