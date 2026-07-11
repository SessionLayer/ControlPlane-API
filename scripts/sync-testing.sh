#!/usr/bin/env bash
#
# Re-vendor the canonical Docker test substrate from the parent testing/ dir.
#
# The authoritative test node (Debian 13 + OpenSSH 10, cert-only) and the Vault
# SSH-engine init live in ../testing (testing/README.md; user directive: never
# rely on host ssh for tests). Because the parent SessionLayer/ folder is NOT a
# git repo and CI checks out THIS repo alone, the test node is VENDORED (committed)
# under src/test/resources/testnode/ and driven via Testcontainers.
#
# Mirrors scripts/sync-contracts.sh. No-op with a note when the source is absent
# (CI or a lone checkout). Keep the vendored copy in sync with the canonical
# source; re-run after any change to testing/.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="../testing"
DST="src/test/resources/testnode"

if [[ ! -d "$SRC/docker/sshd" ]]; then
  echo "[sync-testing] source $SRC/docker/sshd not present (expected in CI or a lone checkout); nothing to do."
  exit 0
fi

mkdir -p "$DST/sshd"
for f in Dockerfile entrypoint.sh sshd_config; do
  cp -v "$SRC/docker/sshd/$f" "$DST/sshd/$f"
done
# Vault SSH-engine init (used by the Vault-backend E2E retrofit of the S3 signer).
cp -v "$SRC/vault-init.sh" "$DST/vault-init.sh"

echo "[sync-testing] vendored test node re-synced from $SRC into $DST"
