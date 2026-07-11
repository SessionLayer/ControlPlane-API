# F-enroll-serial-1: Enrollment leaf serial derived from the gateway id
- Severity: low
- Status: Verified-Fixed
- Area: mtls

## Summary
The enrollment leaf certificate's serial was derived from the gateway_id (also public in the SAN URI),
unlike the CA/renewal paths which use fresh random serials.

## Impact
Predictable/duplicated serial semantics; uniformity/hygiene, not a direct exploit.

## Remediation
Enrollment now uses a fresh random serial (`serial(Uuids.v7())`), matching the renewal path.

## Evidence
`GatewayEnrollmentService.issue` (serial argument).
