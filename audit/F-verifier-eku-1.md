# F-verifier-eku-1: Decision-context verifier trusted the SAN marker alone
- Severity: medium
- Status: Verified-Fixed
- Area: signer

## Summary
`DecisionContextVerifier` accepted any leaf that chained to the mTLS CA and carried the signer URI SAN, without checking
EKU or rejecting a CA cert — a single-point-of-failure for the S10 reference verification.

## Fix
The verifier now also requires the codeSigning EKU and rejects any CA cert. Test `aMarkedLeafWithTheWrongEkuIsRejected`.
