# F-bootstrap-ordering: Bootstrap runner claimed an ordering the config did not enforce

- Severity: low
- Status: Verified-Fixed
- Area: bootstrap

The CA cold-start runner is unordered, so the 'runs after' claim was inaccurate. **Fixed:** comment corrected; correctness rests on ensureSettings idempotency + the single-winner completion flip, not ordering.
