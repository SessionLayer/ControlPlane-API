# F-startup-block-budget: Cumulative bounded-block startup budget (~120s) may exceed a small startupProbe

- Severity: low
- Status: Accepted-Risk
- Area: reliability

CA cold start (≤60s) + first-admin bootstrap (≤30s) + audit partition create-ahead (≤30s) run sequentially. **Justification:** each bounded block deliberately crashes the boot (orchestrator heals) rather than hanging NotReady forever — by design. **Follow-up (runbook):** mandate a k8s startupProbe budget ≥ ~150s.
