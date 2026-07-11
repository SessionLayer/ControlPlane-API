# F-audit-deny-source-1: Deny/error decision-log dropped source IP and swallowed write failures
- Severity: low
- Status: Verified-Fixed
- Area: authz

## Summary
The deny/error audit omitted the source IP (forensics gap) and swallowed its own INSERT failure silently (an FR-AUD-7
gap under audit-DB pressure).

## Fix
`source_ip` is recorded on deny/error audits and a lost audit write is logged at ERROR (observable). The decision stays
fail-closed either way.
