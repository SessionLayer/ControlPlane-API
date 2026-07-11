# F-auth-device-begin-public: beginDeviceFlow publicly reachable via the /v1/auth/device/** glob

- Severity: high
- Status: Verified-Fixed
- Area: rest-security

The permitAll matcher `/v1/auth/device/**` also matched the base path `/v1/auth/device` (beginDeviceFlow), which the contract gates on mTLS — an anti-phishing bypass (attacker begins a flow with a forged SSH source) + unauthenticated unbounded row creation. Converged by redteam-auditor (HIGH) + security-reviewer (HIGH). **Fixed:** PUBLIC_PATHS no longer wildcards the device namespace; only `POST /v1/auth/device/poll` is permitAll; `/v1/auth/device` falls to authenticated, and AuthController additionally requires `AuthMethod.MTLS` (403 otherwise). Regression: RestSecurityIT.beginDeviceFlowRequiresMtlsNotJustAnyCredential (401 unauth, 403 bearer) + devicePollRemainsPublic.
