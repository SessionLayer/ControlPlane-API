# F-compliance-erasure-1: Compliance-mode recordings can only be GDPR-erased by crypto-shred, which the platform cannot perform

- Severity: low
- Status: Accepted-Risk
- Area: security

Governance delete refuses `compliance`-mode objects (object-lock, un-deletable), and the CP holds only the customer PUBLIC key. So for a compliance recording the ONLY erasure path is crypto-shredding — the customer destroying their own private key so the ciphertext becomes unrecoverable — which SessionLayer neither exposes nor performs.

**Justification (by design):** this is the correct WORM-vs-GDPR reconciliation for a max-immutability regime; the platform being unable to erase is the SAME property that makes it unable to decrypt (crown jewels). FR-AUD-6 assigns the GDPR-vs-immutability tension to the operator with platform-provided controls (governance mode + legal hold + retention), which are provided.

**Follow-up (documentation):** name crypto-shred as the compliance-mode erasure mechanism in operator docs; state the operator owns customer-key lifecycle; consider a per-recording WORM-mode override so `compliance` is chosen deliberately per recording rather than only as a cluster default.
