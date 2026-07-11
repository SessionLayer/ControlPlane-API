# F-authz-peer-npe-1: Eager peer.gatewayId() dereference could NPE unaudited
- Severity: info
- Status: Verified-Fixed
- Area: authz

## Summary
`AuthorizationService` dereferenced `peer.gatewayId()` eagerly; a null peer (should not occur on the mTLS-required tier)
would NPE to gRPC UNKNOWN, unaudited.

## Fix
Null-safe caller resolution → the service fail-closes to a generic missing-input deny.
