# F-enroll-oracle-1: Pre-auth gateway-name enumeration oracle on EnrollGateway
- Severity: medium
- Status: Verified-Fixed
- Area: enroll

## Summary
`EnrollGateway` (bootstrap tier, no client cert) parsed the CSR and looked up `findByName` BEFORE
validating the token, returning `FAILED_PRECONDITION "already enrolled"` for a known name vs
`UNAUTHENTICATED "invalid token"` for a free one — an unauthenticated peer could enumerate fleet
gateway names (status AND message differed). Violates NFR-2 / Design §15.

## Impact
Fleet gateway-name disclosure to any peer that can reach the plane, pre-authentication.

## Remediation
`enroll()` now proves a VALID token AND that the name is free before revealing anything: both
"invalid/expired token" and "already enrolled" collapse to ONE generic error (identical status +
description, `UNAUTHENTICATED "enrollment refused"`); the specific reason is audited server-side only;
the single-use token is validated non-destructively (`isValid`) and is NOT burned on a probe. CSR
parse/verify moved AFTER the token check.

## Evidence
`GatewayEnrollmentService.enroll()`; `GatewayEnrollmentTokenService.isValid()`; regression IT
`GatewayIdentityLifecycleIT.enrollErrorIsIndistinguishableForAlreadyEnrolledAndInvalidToken` asserts
identical Status code + description and that the probe token stays unconsumed.
