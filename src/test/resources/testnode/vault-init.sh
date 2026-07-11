#!/usr/bin/env bash
# Enable + configure the Vault SSH secrets engine on the dev `vault` container so
# it can sign OpenSSH user certificates (the SshCertSigner Vault backend, S3).
# Idempotent. Prints the CA public key on stdout (feed it to a node's
# TrustedUserCAKeys). Uses POST /ssh/sign (never /ssh/issue — Design §3.3/D2).
#
#   ./testing/vault-init.sh                 # against docker-compose `vault`
#   VAULT_CONTAINER=my-vault ./testing/vault-init.sh
set -euo pipefail

VAULT_CONTAINER="${VAULT_CONTAINER:-vault}"
MOUNT="${MOUNT:-ssh-client-signer}"
ROLE="${ROLE:-deploy}"
PRINCIPAL="${PRINCIPAL:-deploy}"

vx() { docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=root "$VAULT_CONTAINER" "$@"; }

# Enable the engine if not already mounted.
if ! vx vault secrets list -format=json 2>/dev/null | grep -q "\"${MOUNT}/\""; then
	vx vault secrets enable -path="${MOUNT}" ssh >/dev/null
fi

# Generate an ECDSA P-256 signing CA if absent (matches the platform default, D6).
if ! vx vault read "${MOUNT}/config/ca" >/dev/null 2>&1; then
	vx vault write "${MOUNT}/config/ca" generate_signing_key=true key_type=ec key_bits=256 >/dev/null
fi

# A role that mints short-lived user certs for the given principal.
vx vault write "${MOUNT}/roles/${ROLE}" \
	key_type=ca \
	allow_user_certificates=true \
	allowed_users="${PRINCIPAL}" \
	default_user="${PRINCIPAL}" \
	ttl=5m >/dev/null

# Emit the CA public key (→ node TrustedUserCAKeys).
vx vault read -field=public_key "${MOUNT}/config/ca"
