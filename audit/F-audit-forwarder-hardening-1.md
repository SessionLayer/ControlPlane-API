# F-audit-forwarder-hardening-1: Off-box audit forwarder could hang the audited request and swallowed failures silently

- Severity: medium
- Status: Verified-Fixed
- Area: reliability

The post-commit `AuditForwarder.forward` was awaited inline with no timeout, so a hung/slow forwarder added unbounded latency (and could hang) every audited request (the REST path has no deadline); and a forward failure was `onErrorResume`-swallowed with NO log, contradicting the "logged loudly, never silently dropped" contract.

**Fix (Verified-Fixed, f83a520):** the forward is now bounded by a 5s timeout (a slow/hung forwarder fails best-effort instead of stalling the request) and a failure/timeout is logged at WARN with the event id (the event is already durably committed either way — forwarding never rolls back or fails the audited action).
