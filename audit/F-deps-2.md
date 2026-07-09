# F-deps-2: CVE-2026-0994 on protobuf-java is a false positive (Python-only CVE, version-scheme CPE mismatch)
- Severity: high
- Status: Accepted-Risk
- Area: deps

## Summary
OWASP dependency-check flags `com.google.protobuf:protobuf-java:4.34.2` (a runtime dependency of the
gRPC Handshake server) for CVE-2026-0994 (CVSS 8.2) and, with `failBuildOnCVSS=7`, fails the build.
This is a **false positive**.

## Impact
None. CVE-2026-0994 is a **Python-only** DoS — a recursion-depth bypass in
`google.protobuf.json_format.ParseDict()` on nested `Any` messages. The authoritative GitHub advisory
(GHSA-7gcm-g887-7qv7) lists only the **PyPI** `protobuf` package (affected ≤ 6.33.4, fixed 6.33.5 /
5.29.6), not the Maven `protobuf-java` artifact. NVD models it as `cpe:2.3:a:google:protobuf:*` with
`versionEndIncluding "33.4"` — protobuf's **unified/Python** numbering — and dependency-check
mis-compares Java's `4.34.2` against `33.4` (4 < 33). In unified numbering protobuf-java 4.34.2 is
train 34.2 (newer than 33.4), so the Java artifact is not affected. Independently, this session's only
protobuf use is the Handshake plane over **binary** protobuf on a loopback dev-only path parsing
**trusted** input, with no `Any` fields and no JSON (`JsonFormat`) parsing — the vulnerable code path
is unreachable regardless.

## Remediation
Upgrading is futile (every protobuf-java `4.x` mis-compares as `< 33.4`). Added a **narrowly scoped
suppression** for exactly CVE-2026-0994 on `com.google.protobuf:protobuf-java` in
`config/owasp/dependency-check-suppressions.xml`, with the full justification and a review date
(2026-10-09). Any future, genuinely Java-affecting protobuf CVE has a different id and remains
un-suppressed. Re-evaluate if the NVD CPE is corrected to Java numbering or a real Java advisory
appears.

## Evidence
- CI dependency-check: `protobuf-java-4.34.2.jar (cpe:2.3:a:google:protobuf:4.34.2 ...): CVE-2026-0994(8.2)`.
- NVD CVE-2026-0994: single CPE `cpe:2.3:a:google:protobuf:*`, `versionEndIncluding 33.4`.
- GHSA-7gcm-g887-7qv7: PyPI-only; vulnerable function `json_format.ParseDict()`.
- `contracts/proto/.../handshake.proto`: binary protobuf, no `Any`, no JSON parsing.
