# F-retention-startup-crashloop-1: Blocking retention prune on the ApplicationReady event could crash-loop the whole CP

- Severity: high
- Status: Verified-Fixed
- Area: reliability

`RecordingRetentionJob` ran `prune().block(60s)` inside `@EventListener(ApplicationReadyEvent.class)`; prune() is unbounded, so on a backlog or slow/unreachable WORM store the timeout threw out of the ready-event listener → `SpringApplication.run` rethrows → JVM exit → restart → crash loop, taking down auth/CA/RBAC/audit for a recording-subsystem problem.

**Fix (Verified-Fixed, ddff505):** startup prune is now fire-and-forget `subscribe(...)` with an error log (mirrors `WormObjectStore.warmUp`); the scheduled path likewise never blocks/throws out of a lifecycle callback.
