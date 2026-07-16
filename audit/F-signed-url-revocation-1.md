# F-signed-url-revocation-1: A replay/export signed URL is un-revocable within its TTL and outside the S10 lock spine

- Severity: medium
- Status: Accepted-Risk
- Area: security

Replay/export return a 5-minute presigned GET. Once issued it is a bearer capability: a Lock / JIT-revoke / break-glass-close occurring inside that window does not invalidate it (the S10 dynamic-safety spine never sees the presigned URL), and it cannot be recalled.

**Justification (defensible deviation):** the object is customer-key-encrypted, so a leaked/replayed URL yields **ciphertext only** — the holder still needs the customer private key the platform does not have. The TTL is short (5m, single-object, GET-only) and the URL is returned in the response body (not a 302 `Location` that lands in access logs). This is a genuinely STRONGER confidentiality posture than proxy-based bastions (the platform cannot decrypt) traded for loss of mid-window revocation — a reasonable, explicit trade.

**Mitigations shipped / follow-up:** the URL is never logged; keep the TTL short. A future session could shorten the TTL further, or (if mid-window revocation is required) move replay behind a CP-mediated streaming proxy — at the cost of the platform seeing plaintext, which the crown-jewels model forbids.
