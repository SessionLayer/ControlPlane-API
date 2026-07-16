# F-recording-delete-sod-1: Legal-hold custody and governance-delete share one permission (no segregation of duties)

- Severity: low
- Status: Accepted-Risk
- Area: security

`setRecordingLegalHold` and the governance `deleteRecording` both gate on `recording:delete`, so a single custodian can release a legal hold and then governance-delete the evidence it protected (two audited calls, not prevented). Segregation-of-duties / dual-control would make the hold a stronger insider-destruction control.

**Justification:** spec-compliant — FR-AUD-3/6 model governance delete as "deletable by a specifically-privileged, audited role" (singular); both actions are fully audited (detective control). Splitting the verb or adding dual-control is an additive future enhancement, not required by the spec, and introduces another permission + migration late in this session.

**Follow-up:** a future session may split `recording:legal_hold` (custody) from `recording:delete` (erasure) and/or require two-person integrity for hold-release + governance delete.
