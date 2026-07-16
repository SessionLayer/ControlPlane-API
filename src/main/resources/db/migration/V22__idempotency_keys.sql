-- V22 — idempotency-key store (API conventions, FR-API-1). SessionLayer CP, Session 17.
--
-- A mutating request MAY carry an `Idempotency-Key` header; the CP records the first
-- completed response keyed by (principal, method, path, key) so a retry replays it
-- instead of repeating the side effect. RUNTIME (per-request operational state): no
-- `origin`. cp_runtime auto-gets CRUD via the V11 default privileges. The store is
-- bounded by `expires_at` (a background/opportunistic sweep prunes expired rows).
--
-- request_fingerprint = SHA-256 over (method, path, canonical request body); a reused
-- key with a DIFFERENT fingerprint is a 422 (never a wrong-body replay). response_body
-- holds the serialized success/deterministic response (may be NULL for 204/empty).

CREATE TABLE runtime.idempotency_key (
    id                  uuid        PRIMARY KEY,
    principal           text        NOT NULL,
    method              text        NOT NULL,
    path                text        NOT NULL,
    idempotency_key     text        NOT NULL,
    request_fingerprint text        NOT NULL,
    response_status     integer     NOT NULL CHECK (response_status BETWEEN 100 AND 599),
    response_body       text,
    version             bigint      NOT NULL DEFAULT 0,
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    UNIQUE (principal, method, path, idempotency_key)
);
COMMENT ON TABLE runtime.idempotency_key IS 'FR-API-1: Idempotency-Key replay store; first completed response per (principal, method, path, key). RUNTIME, bounded by expires_at.';

CREATE INDEX idempotency_key_expires_idx ON runtime.idempotency_key (expires_at);
