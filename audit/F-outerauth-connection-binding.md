# F-outerauth-connection-binding: device-flow connection_binding is a dead field
- Severity: info
- Status: Verified-Fixed
- Area: outerauth

## Summary
`OuterLegAuthService.beginDeviceFlow` mints `Secrets.randomToken(32)` as a `connectionBinding` and
`DeviceFlowService` persists it through create/authorized, but no path ever reads or compares it (grep:
all writes, zero comparisons). The `DeviceFlow` javadoc and the mint-site comment described it as "the
1:1 device_code↔connection anti-phishing binding", which overstated its role.

## Impact
None (not exploitable). The real 1:1 device_code↔connection binding is device_code secrecy: the
device_code is a 32-byte random token, per-connection, stored only as its SHA-256, and never logged
(`DeviceFlow.deviceCodeHash`, `Secrets.sha256Hex`). The dead field neither adds nor removes any
guarantee; the risk was purely a misleading name/comment (RC-1, T3 review).

## Remediation
Documented as reserved, not dropped (per the review steer — dropping the nullable `connection_binding`
column would need a migration for no security gain). The `DeviceFlow` record javadoc and the
`OuterLegAuthService.beginDeviceFlow` mint-site comment now state it is a reserved field no path reads,
and that device_code secrecy is the actual binding. The merged V9 migration is left untouched.

## Evidence
- `grpc/OuterLegAuthService.beginDeviceFlow` (mint-site comment).
- `data/runtime/DeviceFlow` (record javadoc); the field is written by `create`/`authorized`/`withStatus`
  and read by no comparator anywhere in the tree.
- Real binding: `device/DeviceFlowService` (device_code = `Secrets.randomToken(32)`, stored as
  `Secrets.sha256Hex`); poll/approve key off the device_code hash, never `connection_binding`.
