# F-outerauth-device-groups: device-flow ResolvedIdentity carries empty groups
- Severity: low
- Status: Accepted-Risk
- Area: outerauth

## Summary
`OuterLegAuthService.pollDeviceFlow` populates `ResolvedIdentity{resolved,identity}` on APPROVED but
leaves `groups` empty. The `runtime.device_flow` row does not persist the OIDC groups resolved at the
CP verification-page callback (`DeviceFlowService.Status` carries only `identity`), so there is nothing
to echo here.

## Impact
Group-based RBAC selectors do not apply to a device-flow login: the Gateway calls `Authorize` with an
empty `identity_groups` for device-flow authentications. This is a reduction in expressiveness, not a
bypass — `Authorize` is deny-by-default and still evaluates identity/principal rules; a group-scoped
grant simply will not match for a device-flow login. The proto explicitly permits empty groups.

## Remediation
Accepted for this session: the frozen `ResolvedIdentity.groups` is documented as "may be empty", and
principals are also empty for device flow (RBAC alone decides the logins, per the contract). Persisting
the callback-resolved OIDC groups onto `runtime.device_flow` (a small additive column) and returning
them here is a clean follow-up if group-scoped device-flow grants are required; it needs a migration
(next free V17) and a `DeviceFlowService.approve` change to store the groups.

## Evidence
- `grpc/OuterLegAuthService.toPollResponse` (groups = `List.of()` on APPROVED, with a WHY comment).
- `data/runtime/DeviceFlow` (no groups column); `device/DeviceFlowService.Status` (no groups field).
