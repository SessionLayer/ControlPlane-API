# F-device-source-failopen: Enforced device source-match failed open on an indeterminate correlation

- Severity: medium
- Status: Verified-Fixed
- Area: device

`deny = enforce && Boolean.FALSE.equals(match)` allowed a `null` (unknown) correlation even under enforcement, so blanking a source bypassed the binding (NFR-2 violation). **Fixed:** `deny = enforce && !Boolean.TRUE.equals(match)` (unknown → deny under enforcement).
