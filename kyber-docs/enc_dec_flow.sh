#!/usr/bin/env bash
set -euo pipefail

# Requires jq for parsing JSON
command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }

: "${VAULT_ADDR:?set VAULT_ADDR, e.g. http://127.0.0.1:8200}"
: "${VAULT_TOKEN:?set VAULT_TOKEN, e.g. root}"

# ---- Config ----
KEY_NAME=${KEY_NAME:-my-kyber22}      # override with KEY_NAME=foo ./encdec_flow.sh
KEY_SIZE=${1:-${KEY_SIZE:-768}}       # arg > env > default(768)

case "$KEY_SIZE" in
  512)   KEY_TYPE="kyber512" ;;
  768)   KEY_TYPE="kyber768" ;;
  1024)  KEY_TYPE="kyber1024" ;;
  kyber512|kyber768|kyber1024) KEY_TYPE="$KEY_SIZE" ;;  # allow passing full type
  *) echo "Use 512, 768, 1024 or kyber512|kyber768|kyber1024"; exit 1 ;;
esac

echo "Using key name: $KEY_NAME"
echo "Using key type: $KEY_TYPE"

echo "== Enable Transit =="
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/sys/mounts/transit" \
  -d '{"type":"transit"}' >/dev/null || true

echo "== Create Kyber key ($KEY_NAME, $KEY_TYPE) =="
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/keys/$KEY_NAME" \
  -d "{\"type\":\"$KEY_TYPE\"}" >/dev/null || true

echo "== Encrypt with Kyber, capture ciphertext =="
PLAINTEXT_B64=$(printf 'hello kyber' | base64)
CT=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST -d "{\"plaintext\":\"$PLAINTEXT_B64\"}" \
  "$VAULT_ADDR/v1/transit/encrypt/$KEY_NAME" \
  | jq -r .data.ciphertext)

echo "Ciphertext (CT): ${CT:0:80}..."

echo "== Decrypt using captured CT =="
DEC_B64=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST -d "{\"ciphertext\":\"$CT\"}" \
  "$VAULT_ADDR/v1/transit/decrypt/$KEY_NAME" \
  | jq -r .data.plaintext)

echo "Decrypted (base64): $DEC_B64"
echo "Decoded: $(echo "$DEC_B64" | base64 -d)"
