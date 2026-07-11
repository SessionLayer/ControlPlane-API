# F-lock-ingest-validation-1: A typo-d/empty lock target evaluates as match-all
- Severity: low
- Status: Accepted-Risk
- Area: authz

## Summary
An empty or unrecognized-facet lock target matches everything (fail closed), so a typo could over-block.

## Justification
There is NO lock-create surface this session (the lock API is S6+), so ingest-time validation has nothing to attach to;
the evaluation direction is correct (over-block, never under-block). Recommendation carried to the lock-create session:
reject empty/unrecognized targets at ingest and require an explicit {all:true} for an intentional global lock.
