# F-retention-claim-delete-residual-1: Claim-then-delete leaves a pruned-but-present object if the object delete fails after the row claim

- Severity: low
- Status: Accepted-Risk
- Area: reliability

The legal-hold TOCTOU fix (F-legalhold-prune-toctou-1) claims the `recording_ref` row (marks it pruned) BEFORE deleting the object. If the object-store delete fails AFTER a successful claim, the row reads pruned while the (still customer-key-encrypted) object may persist; the failure is logged WARN for ops reconciliation.

**Justification:** claim-first is the correct ordering — the alternative (delete-first) reopens the held-erasure TOCTOU (erasing an object whose row a concurrent legal hold just protected), which is far worse (spoliation). Object-store deletes are reliable, so the residual is rare, it is loudly logged, the leftover object is encrypted (no confidentiality impact), and `pruned_at`-marked rows are trivially reconcilable.

**Follow-up:** a periodic reconciliation pass that re-attempts the object delete for `pruned_at`-marked rows whose object still lists.
