# F-s17-jitpolicy-selector-1: A malformed jit_policy targetSelector created via the API breaks JIT-request submit fleet-wide (500)

- Severity: high
- Status: Verified-Fixed
- Area: jit / config-api

## Summary
The new `POST /v1/jit-policies` surface (S17) let an operator persist a `targetSelector` in a shape the
S5 evaluator (`authz/Selectors.labelMatches`) cannot parse — e.g. `{"env":"prod"}` (a bare string where a
condition object `{"op":"eq","value":"prod"}` is required). `JitLifecycleService.matchingPolicy` then does
`policies.findAll().filter(p -> Selectors.labelMatches(p.targetSelector(), labels))` over EVERY jit_policy
on the JIT-request **submit** path; a single malformed row makes `labelMatches` throw
(`requireObject("label condition")`), the reactive chain errors, and `POST /v1/jit-requests` returns **500
for every requester** — a self-inflicted availability outage triggered by one valid-looking admin API call.
Unlike the S5 `DenyOverridesPolicyEngine` (which catches selector errors and fails closed), the JIT submit
path had no such guard. It also violates FR-API-5 (invalid config must be rejected pre-commit).

## Failure scenario
1. An admin `POST /v1/jit-policies` with `{"targetSelector": {"env": "prod"}, ...}` → **201** (accepted — the
   CRUD did not validate the selector shape).
2. Any user `POST /v1/jit-requests` for any node → `matchingPolicy` iterates all policies, hits the bad row,
   `labelMatches` throws → **500**. JIT access is broken platform-wide until the bad policy is deleted.

Discovered by CI: `JitCrudIT.submitPendsThenApproverActivates` / `selfApprovalIsForbidden` returned 500 once
`JitPolicyCrudIT` (sharing the singleton test Postgres) had created such policies.

## Fix (Verified-Fixed)
Defense in depth — prevent the bad config AND tolerate any that already exists:
1. **Pre-commit validation (primary, FR-API-5).** New `configapi/SelectorValidation` runs a candidate
   selector through the SAME evaluator with dummy inputs; a shape it can't parse is a `422`
   (`ApiProblemException.validation`). Wired into `JitPolicyConfigService` (`targetSelector`) and
   `RuleConfigService` (`identitySelector`/`nodeLabelSelector`/`sourceIpCondition`) so the config CRUD
   accepts exactly the selector shapes the evaluator accepts.
2. **Fail-closed matcher (defense in depth).** `JitLifecycleService.matchingPolicy` now skips a policy whose
   selector throws (logs a WARN, treats it as non-matching) — matching the S5 engine's documented posture, so
   one malformed row (from any source) can never 500 submit again.
3. Tests `RuleCrudIT`/`JitPolicyCrudIT` corrected to use the valid condition-object selector shape.

Verified: `JitCrudIT` + `JitPolicyCrudIT` + `RuleCrudIT` green together; the invalid shape now returns `422`
pre-commit and never persists.
