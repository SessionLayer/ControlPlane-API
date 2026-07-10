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
#                        (dependency CVE management is handled by Dependabot)
#   2. contracts/lint.sh — buf lint + buf breaking + redocly OpenAPI lint
#   3. audit findings    — the NO-DEFER gate (§4.2): zero OPEN findings of ANY
#                          severity, and NO finding may be `Deferred`.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> [1/3] ./mvnw -B -ntp verify"
./mvnw -B -ntp verify

echo "==> [2/3] contracts/lint.sh"
./contracts/lint.sh

echo "==> [3/3] audit findings check (NO-DEFER: zero open of ANY severity + no Deferred)"
# The standing directive is "never defer anything": block on ANY finding whose Status
# is Open (any severity — critical|high|medium|low|info), and reject the `Deferred`
# status entirely. Accepted-Risk (with explicit written justification, §2.1) is the
# only non-Verified-Fixed status allowed and does NOT count as open. Parse fail-closed:
# an unparseable status blocks too.
open=0
deferred=0
bad=0
shopt -s nullglob
for f in audit/F-*.md; do
	st=$(grep -iE '^- *Status:' "$f" | head -1 | sed -E 's/.*Status:[[:space:]]*//I' | tr 'A-Z' 'a-z' | tr -cd 'a-z-')
	case "$st" in
	verified-fixed | accepted-risk)
		: # allowed
		;;
	open)
		echo "OPEN finding: $f"
		open=$((open + 1))
		;;
	deferred)
		echo "DEFERRED finding (banned by the no-defer gate): $f"
		deferred=$((deferred + 1))
		;;
	*)
		echo "UNPARSEABLE/unknown status ('$st'): $f"
		bad=$((bad + 1))
		;;
	esac
done
total=$((open + deferred + bad))
[ "$total" -gt 0 ] && {
	echo "findings gate FAILED: $open open, $deferred deferred, $bad unparseable"
	exit 1
}
echo "gate OK"
