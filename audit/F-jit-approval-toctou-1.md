# F-jit-approval-toctou-1: an approval landing after the window granted a fresh full TTL
- Severity: medium
- Status: Verified-Fixed
- Area: jit

## Summary
`JitLifecycleService.act` checked only `state == PENDING_APPROVAL`, never the approval-window clock. A
final approval landing after `approval_deadline` but before the periodic sweep (default 5m) flipped the
request to APPROVED and started a fresh grant clock — the approval window was effectively unbounded up
to the sweep interval.

## Impact
An approver acting minutes past the deadline still granted a full-TTL JIT session, defeating the
approval-window control. Bounded (to the sweep interval) but a real time-of-check/time-of-use gap.

## Fix
`act` now, immediately after the PENDING_APPROVAL check, rejects when the approval window has elapsed:
it lazily flips the request to EXPIRED (+ `jit.expired` audit, symmetric with the grant path's
read-time expiry) and returns `NOT_PENDING`. Regression test
`JitLifecycleIT.anApprovalAfterTheWindowIsRejectedAndTheRequestExpires`.
