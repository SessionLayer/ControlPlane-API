# F-basic-username-timing: Basic escape-hatch username compared non-constant-time

- Severity: low
- Status: Verified-Fixed
- Area: rest-security

Short-circuit String.equals leaked username existence via timing. **Fixed:** constant-time username compare + both factors evaluated (BCrypt always runs).
