# F-authz-cap-bleed-1: Capabilities unioned across grants for other principals (capability over-grant)
- Severity: medium
- Status: Verified-Fixed
- Area: authz

## Summary
Capabilities were the union of ALL identity-matching allows, so capabilities from a grant for a different login
(including agent_forward/x11) bled onto the connect.

## Fix
Capabilities/TTL/representative are scoped to the allows that grant the CHOSEN login (gated per grant, FR-AUTHZ-6);
`allowed_logins` stays a union. Regression test `capabilitiesDoNotBleedAcrossPrincipals`.
