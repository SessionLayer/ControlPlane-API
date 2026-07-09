#!/usr/bin/env bash
#
# Contract lint gate — the single entrypoint for validating the frozen
# cross-repo contracts. Runs:
#   1. buf lint        — protobuf style/consistency
#   2. buf breaking     — protobuf backward-compat vs the main baseline
#   3. redocly lint     — OpenAPI 3.1 validation
#
# Runnable locally (`contracts/lint.sh`) and from CI. Requires `buf` and a
# Node/npx toolchain on PATH. Exits non-zero on any violation.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here"

# Pin the OpenAPI linter so local and CI agree.
REDOCLY_VERSION="${REDOCLY_VERSION:-1.34.5}"

red() { printf '\033[31m%s\033[0m\n' "$*"; }
grn() { printf '\033[32m%s\033[0m\n' "$*"; }

echo "==> [1/3] buf lint"
( cd proto && buf lint )
grn "    buf lint: OK"

echo "==> [2/3] buf breaking (against main baseline)"
# On the first introduction of the module (main has no contracts/proto yet)
# there is no baseline to compare against; treat that as a pass. Any other
# failure is a real breaking change and fails the gate.
breaking_err="$(mktemp)"
trap 'rm -f "$breaking_err"' EXIT
if ( cd proto && buf breaking --against "${here}/../.git#branch=main,subdir=contracts/proto" ) 2>"$breaking_err"; then
  grn "    buf breaking: OK"
else
  if grep -qiE 'does not (exist|contain)|no( such)? .*\.proto|could not (find|resolve)|unknown revision|invalid ref' "$breaking_err"; then
    grn "    buf breaking: no baseline module on main yet (first introduction) — skipped"
  else
    red "    buf breaking: FAILED"
    cat "$breaking_err" >&2
    exit 1
  fi
fi

echo "==> [3/3] redocly lint (OpenAPI 3.1)"
npx --yes "@redocly/cli@${REDOCLY_VERSION}" lint openapi/openapi.yaml
grn "    redocly lint: OK"

grn "==> contracts: all checks passed"
