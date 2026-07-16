# F-s17-config-affordances-1: no dry-run/bulk/history endpoints and no filtering on config list collections

- Severity: low
- Status: Accepted-Risk
- Area: config-api

## Summary
The config CRUD has no server-side dry-run/validate endpoint, no bulk/atomic multi-resource apply, no config
revision history/soft-delete, and the config LIST collections (rules/roles/role-bindings/cas/…) take no
filter params (only `sessions`/`recordings`/`audit-events` filter). Reference admin systems offer some of
these.

## Justification (Accepted-Risk)
S17's scope is the full CRUD surface + the API conventions + the complete-contract freeze — not operator
affordances. Every item here is **cleanly additive** to the frozen contract (new optional query params, new
endpoints) and can land in a future session without a breaking change or a new URI major, so freezing without
them costs nothing forward. Pre-commit validation already gives create/update a 422 that doubles as a
"would this be accepted?" check. **Recommended:** add `name`/`origin` filters to the config lists and a
`?dryRun=true` validation mode in a later session. Consciously deferred, not overlooked.
