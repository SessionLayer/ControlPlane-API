-- S30: Authorize now looks up a usable JIT grant UNCONDITIONALLY on every
-- connect (not just when standing access fails outright), so the lookup query
-- needs an index that answers it directly rather than scanning every
-- historical row for the requester and filtering in the application. Partial
-- (state-scoped) + covering the exact predicate the query now uses.
CREATE INDEX idx_jit_request_usable ON runtime.jit_request (requester, target_node_id, principal, grant_expires_at)
    WHERE state IN ('APPROVED', 'ACTIVE');

COMMENT ON INDEX runtime.idx_jit_request_usable IS
    'Backs JitRequestRepository.findUsableGrant (S30): a point lookup instead of a per-requester scan.';
