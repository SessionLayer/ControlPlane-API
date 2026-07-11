# F-authz-effect-failclosed-1: A mislabeled dp_rule.effect failed open
- Severity: low
- Status: Verified-Fixed
- Area: authz

## Summary
A rule whose `effect` was neither `allow` nor `deny` was dropped from both sets; if the DB CHECK were ever bypassed a
mislabeled deny would fail open.

## Fix
Any non-`allow` effect is treated as a deny (fail closed regardless of the DB CHECK). Test `unknownEffectIsTreatedAsDeny`.
