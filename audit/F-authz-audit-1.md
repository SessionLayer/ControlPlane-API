# F-authz-audit-1: Fail-closed authz denials were not audited (FR-AUD-7)
- Severity: medium
- Status: Verified-Fixed
- Area: audit

## Summary
Only successes and the renew generation-mismatch were audited; enroll/sign/renew fail-closed denials
were not, so FR-AUD-7 ("all auth/authz decisions recorded") was unmet on the denial paths.

## Impact
Incomplete audit trail: a Gateway's rejected enroll/sign/renew attempts left no record for the
Auditor / incident response.

## Remediation
Denials now emit a generic, secret-free `audit(..., "denied", ...)` with the caller id + a category
reason kept server-side (never on the wire): enroll (invalid-token / already-enrolled), sign (single
`onErrorResume` over the signing path), renew (inactive / fingerprint-mismatch), plus the existing
generation-mismatch flag. The client-visible error stays generic.

## Evidence
`GatewayEnrollmentService.enroll` denial branch; `SessionCertificateService.sign` onErrorResume;
`GatewayRenewalService.denied()`.
