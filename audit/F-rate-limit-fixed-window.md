# F-rate-limit-fixed-window: Fixed-window rate limiter allows a ~2x burst at a window boundary

- Severity: low
- Status: Accepted-Risk
- Area: reliability

A boundary-straddling burst can pass up to 2*max in a ~1ms span. **Justification:** acceptable for auth throttling (the goal is bounding sustained brute-force, not smoothing); a sliding-window/token-bucket is a future refinement if precise smoothing is required.
