# F-public-row-creation: Unbounded persistent-row creation on public auth endpoints

- Severity: medium
- Status: Verified-Fixed
- Area: reliability

beginDeviceFlow (public via the glob) + /v1/auth/verify accumulated device_flow/oidc_login rows unthrottled. **Fixed:** begin is now mTLS-gated (F-auth-device-begin-public), /v1/auth/verify is rate-limited, and the auth reaper (F-auth-reaper) bounds growth.
