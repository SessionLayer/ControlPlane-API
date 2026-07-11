# F-bootstrap-credential-ttl: Printed-once first-admin credential has no time-based expiry

- Severity: low
- Status: Accepted-Risk
- Area: bootstrap

The armed bootstrap credential stays valid until claimed or until any admin exists (it self-disables then), with no clock TTL. **Justification:** 192-bit, stored hashed, single-use, emitted once at startup on an unconfigured system where the operator claims it immediately by design (the 'surrender on first login' model, §2A). It self-disables the moment a platform admin exists. **Follow-up:** add an armed-at TTL column + auto-rearm, matching Teleport/K8s bootstrap-token TTLs.
