# F-authz-blank-input-1: Blank identity/principal could allow + mint on the connect path
- Severity: medium
- Status: Verified-Fixed
- Area: authz

## Summary
A blank `identity` matched `{all:true}` rules and a blank `requested_principal` skipped the principal check and minted
a null-principal token/ssh_session.

## Fix
`ConnectAuthorizationService.authorize` treats a blank identity or requested principal as fail-closed missing input
(also closes the null-principal token/NPE variant).
