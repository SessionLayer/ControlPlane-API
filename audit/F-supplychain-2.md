# F-supplychain-2: Release jar not reproducible off-runner — JDK pinned only to major '25'

- Severity: medium
- Status: Verified-Fixed
- Area: supplychain

## Issue

`.github/workflows/release.yml` set up the build JDK with
`actions/setup-java` `java-version: '25'`, which resolves to whichever Temurin
25.0.x is current when the workflow runs. The Spring Boot jar manifest embeds
`Created-By` / `Build-Jdk-Spec` (the JDK version), so the same source tag rebuilt
months later on a newer 25.0.y produces a **different jar digest**.

## Impact

The in-workflow double-build reproducibility gate runs both builds on the *same*
runner in the *same* run, so it cannot catch this: it only proves same-JDK
determinism. An independent verifier (NFR-7's third-party-verifiability goal)
rebuilding later gets a mismatching digest through no fault of the source —
undermining the point of a reproducible build.

## Fix

Pin the exact Temurin build: `java-version: '25.0.3+9'` (a real current Adoptium
GA release), with a comment marking it as the reproducibility precondition,
bumped deliberately in lockstep with a re-tag. `ci.yml` (the required `gate`,
which produces no release artifact) intentionally stays on floating `'25'` so
tests keep exercising the latest patch.

## Resolution (Session 22)

release.yml now pins `java-version: '25.0.3+9'`. The reproducible jar digest is
therefore anchored to a fixed JDK across time, not just within one run.
