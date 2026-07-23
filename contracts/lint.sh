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
# Compare the contracts/proto module against its state on `main`. Decide whether
# a baseline exists by asking git DIRECTLY (robust) rather than parsing buf's
# error text: there is nothing to diff when either
#   (a) no `main` ref is available locally — e.g. a shallow CI checkout that did
#       not fetch main (actions/checkout without fetch-depth: 0), or
#   (b) `main` has no contracts/proto module yet — the first introduction.
# In both cases skip cleanly. Once `main` HAS the module (Session Two onward) and
# CI fetches it (fetch-depth: 0), the real breaking-change gate runs.
repo_root="$(git -C "$here" rev-parse --show-toplevel)"
base_ref=""
for r in origin/main main; do
  if git -C "$here" rev-parse --verify --quiet "${r}^{commit}" >/dev/null 2>&1; then
    base_ref="$r"
    break
  fi
done
if [ -z "$base_ref" ]; then
  # In CI this must never be a silent skip — that is exactly the class of bug
  # this repo exists to prevent (S28). A missing main ref there means the
  # checkout step regressed (e.g. lost its fetch-depth: 0), not that there is
  # nothing to compare against. Only an ad-hoc local shallow clone gets the
  # quiet skip.
  if [ -n "${CI:-}" ] || [ -n "${GITHUB_ACTIONS:-}" ]; then
    red "    buf breaking: FAILED — no 'main' ref available in CI (checkout likely missing fetch-depth: 0)"
    exit 1
  fi
  grn "    buf breaking: no 'main' ref available locally (shallow checkout) — skipped"
elif ! git -C "$here" cat-file -e "${base_ref}:contracts/proto/buf.yaml" 2>/dev/null; then
  grn "    buf breaking: 'main' has no contracts/proto baseline yet (first introduction) — skipped"
else
  base_sha="$(git -C "$here" rev-parse "${base_ref}")"
  ( cd proto && buf breaking --against "${repo_root}/.git#ref=${base_sha},subdir=contracts/proto" )
  grn "    buf breaking: OK (baseline ${base_ref} @ ${base_sha:0:12})"
fi

echo "==> [3/3] redocly lint (OpenAPI 3.1)"
npx --yes "@redocly/cli@${REDOCLY_VERSION}" lint openapi/openapi.yaml
grn "    redocly lint: OK"

grn "==> contracts: all checks passed"
