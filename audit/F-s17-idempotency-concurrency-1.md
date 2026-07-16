# F-s17-idempotency-concurrency-1: two exactly-concurrent same-key requests can both execute

- Severity: low
- Status: Accepted-Risk
- Area: config-api

## Summary
`IdempotencyService` is lookup-then-act-then-record: two requests with the same key that both miss the lookup
before either records can both run the action (Stripe returns 409 "in progress" for an in-flight key).

## Justification (Accepted-Risk)
The RETRY case — the one the gate specifies and the common one — is fully deduplicated (the second sequential
request replays the first response, no double-execute). The exactly-concurrent residual is bounded: a
duplicate CREATE is rejected by the resource's unique-name constraint (the second gets 409), and a duplicate
`rotate`/`terminate` is benign/idempotent in effect. A fully concurrency-safe design (reserve the key in a
"pending" row BEFORE the action, then have the loser poll/replay) adds meaningful complexity for a
narrow window and is a candidate future enhancement. Documented, not silently ignored.
