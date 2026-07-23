#!/usr/bin/env bash
#
# Vendor the frozen contracts from SessionLayer/Contracts, pinned by
# contracts.lock (tag + resolved commit SHA). ControlPlane-API is a consumer
# of this repo just like Gateway/Agent/Dashboard — contracts/ here is no
# longer hand-edited; it's fetched + pinned from the canonical repo. This
# script does a REAL git clone of the pinned tag and verifies the resolved
# commit SHA matches contracts.lock before copying anything, so a moved or
# re-pushed tag can't silently swap content. Git-only: no GitHub API token, no
# hosted registry, works fully offline once the tag is fetched.
#
# Usage:
#   scripts/vendor-contracts.sh          # fetch + re-vendor, then review + commit
#   scripts/vendor-contracts.sh --check  # fetch + diff only; exit non-zero on drift
set -euo pipefail
cd "$(dirname "$0")/.."

LOCK="contracts.lock"
DST="contracts"
mode="${1:-sync}"

repo=$(sed -n 's/^repo=//p' "$LOCK")
tag=$(sed -n 's/^tag=//p' "$LOCK")
want_sha=$(sed -n 's/^sha=//p' "$LOCK")

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git clone --quiet --depth 1 --branch "$tag" "https://github.com/${repo}.git" "$tmp/src"
got_sha="$(git -C "$tmp/src" rev-parse HEAD)"
if [ "$got_sha" != "$want_sha" ]; then
  echo "DRIFT: ${repo}@${tag} resolves to ${got_sha}, but ${LOCK} pins ${want_sha}." >&2
  echo "       The tag may have moved. Refusing to vendor without a reviewed contracts.lock update." >&2
  exit 1
fi

SRC="$tmp/src/contracts"

case "$mode" in
  --check)
    if diff -rq "$SRC" "$DST" >"$tmp/diff" 2>&1; then
      echo "in sync: ${DST}/ matches ${repo}@${tag}:contracts/"
    else
      echo "DRIFT: ${DST}/ differs from ${repo}@${tag}:contracts/" >&2
      cat "$tmp/diff" >&2
      exit 1
    fi
    ;;
  sync)
    rsync -a --delete "$SRC"/ "$DST"/
    echo "Vendored from ${repo}@${tag} (${got_sha:0:12}). Review the diff, regenerate, and commit."
    ;;
  *)
    echo "usage: $0 [--check]" >&2
    exit 2
    ;;
esac
