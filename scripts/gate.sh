#!/usr/bin/env bash
#
# ControlPlane-API ROUND_FINAL gate.
#
# Self-contained: used by CI (.github/workflows/ci.yml), `make cp-gate`, and the
# project hook. Runs the full Java gate + the contract lint + the audit findings
# check, and exits non-zero on any failure.
#
#   1. ./mvnw verify   — codegen (proto + OpenAPI) + compile + spotless:check
#                        + checkstyle:check + unit tests + Testcontainers IT
#                        + OWASP dependency-check (fails on CVSS >= 7)
#   2. contracts/lint.sh — buf lint + buf breaking + redocly OpenAPI lint
#   3. audit findings    — zero OPEN medium+ (critical|high|medium) findings
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> [1/3] ./mvnw -B -ntp verify"
# Forward an NVD API key to OWASP dependency-check when the environment provides
# one (CI passes NVD_API_KEY from the repo secret). Empty is fine — the plugin
# then uses unauthenticated (rate-limited) NVD access.
./mvnw -B -ntp verify -DnvdApiKey="${NVD_API_KEY:-}"

echo "==> [2/3] contracts/lint.sh"
./contracts/lint.sh

echo "==> [3/3] audit findings check (zero open medium+)"
open=0
shopt -s nullglob
for f in audit/F-*.md; do
	sev=$(grep -iE '^- *Severity:' "$f" | head -1 | sed -E 's/.*Severity:[[:space:]]*//I' | tr 'A-Z' 'a-z' | tr -cd 'a-z')
	st=$(grep -iE '^- *Status:' "$f" | head -1 | sed -E 's/.*Status:[[:space:]]*//I' | tr 'A-Z' 'a-z' | tr -cd 'a-z-')
	case "$sev" in
	critical | high | medium)
		[ "$st" = open ] && {
			echo "OPEN $sev: $f"
			open=$((open + 1))
		}
		;;
	esac
done
[ "$open" -gt 0 ] && {
	echo "$open open medium+ finding(s)"
	exit 1
}
echo "gate OK"
