# F-auth-reaper: Transient auth tables grew unbounded (no reaper; a false 'prune exists' claim)

- Severity: medium
- Status: Verified-Fixed
- Area: reliability

consumed_assertion / auth_rate_limit / oidc_login / device_flow / otp had no prune. **Fixed:** AuthMaintenanceService prunes expired rows on startup + hourly (gated, fail-soft).
