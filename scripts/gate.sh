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

# Fast, dependency-free first: the wire-conformance golden must match its committed
# provenance (frames.json's own sha256 + the sha256 of every input proto it was generated
# from). This closes the drift hole (G-b): framegen is a manual dev tool that never runs in
# CI, so without this a stale golden (proto changed, not regenerated) or a hand-edited
# frames.json would propagate to both Rust repos and both conformance suites would pass
# against the WRONG oracle. Pure sha256 — no Rust toolchain needed in the Java pipeline.
# On any mismatch: `make wire-conformance` regenerates the golden + provenance together.
echo "==> [1/4] wire-conformance golden integrity (frames.json vs provenance)"
prov="contracts/wire/conformance/frames.provenance"
if [ ! -f "$prov" ]; then
	echo "missing $prov — regenerate with 'make wire-conformance'"
	exit 1
fi
sha_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
golden_fail=0
while IFS=$'\t' read -r rel want; do
	case "$rel" in '' | \#*) continue ;; esac
	got=$(sha_of "contracts/$rel")
	if [ -z "$got" ]; then
		echo "GOLDEN: cannot read contracts/$rel"
		golden_fail=1
	elif [ "$got" != "$want" ]; then
		echo "GOLDEN DRIFT: contracts/$rel sha256 $got != recorded $want"
		golden_fail=1
	fi
done <"$prov"
[ "$golden_fail" -eq 0 ] || {
	echo "wire-conformance golden drifted — regenerate with 'make wire-conformance' and commit;"
	echo "frames.json is machine-generated and MUST NOT be hand-edited (a wrong golden is a worse oracle than none)."
	exit 1
}
echo "golden integrity OK"

echo "==> [2/4] ./mvnw -B -ntp verify"
./mvnw -B -ntp verify

echo "==> [3/4] contracts/lint.sh"
./contracts/lint.sh

echo "==> [4/4] audit findings check (NO-DEFER: zero open of ANY severity + no Deferred)"
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
