# F-audit-search-window-1: Audit search had no max time window — unbounded scans over the partitioned audit_event table

- Severity: medium
- Status: Verified-Fixed
- Area: reliability

`audit_event` is range-partitioned by `occurred_at` monthly, but the search keyset on `id` clamped only page size and enforced no time bound, so a query without a time filter could not prune partitions (MergeAppend across every monthly partition, growing unbounded with age). SESSION §8 listed "max time window" as an open value to set; it was absent.

**Fix (Verified-Fixed, c264ac2):** `sessionlayer.audit.search.{default-window=90d, max-window=366d}`. An unfiltered search defaults `from = now - default-window` (prunes to recent partitions); an explicit `[from,to]` within max passes through verbatim; a span exceeding max is a 422 (semantic rejection of well-formed input, per repo convention). Documented §8 open values; `AuditSearchWindowIT` proves both paths.
