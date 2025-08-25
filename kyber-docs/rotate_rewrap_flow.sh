#!/usr/bin/env bash
set -euo pipefail

# Requires jq
command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 1; }

: "${VAULT_ADDR:?set VAULT_ADDR, e.g. http://127.0.0.1:8200}"
: "${VAULT_TOKEN:?set VAULT_TOKEN, e.g. root}"

# ---- Config ----
KEY_NAME=${KEY_NAME:-test-kyber}        # use a fresh name to see v1->v2 clearly
KEY_SIZE=${1:-${KEY_SIZE:-768}}         # arg > env > default(768)

case "$KEY_SIZE" in
  512)   KEY_TYPE="kyber512" ;;
  768)   KEY_TYPE="kyber768" ;;
  1024)  KEY_TYPE="kyber1024" ;;
  kyber512|kyber768|kyber1024) KEY_TYPE="$KEY_SIZE" ;;
  *) echo "Use 512, 768, 1024 or kyber512|kyber768|kyber1024"; exit 1 ;;
esac

echo "Using key name: $KEY_NAME"
echo "Using key type: $KEY_TYPE"

# ---- Enable Transit ----
echo "== Enable Transit (idempotent) =="
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/sys/mounts/transit" \
  -d '{"type":"transit"}' >/dev/null || true

# ---- Create Key ----
echo "== Create Kyber key ($KEY_NAME, $KEY_TYPE) =="
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/keys/$KEY_NAME" \
  -d "{\"type\":\"$KEY_TYPE\"}" >/dev/null || true

# ---- Encrypt v1 ----
echo "== Encrypt some data with version 1 =="
PLAINTEXT1_B64=$(printf 'hello kyber' | base64)
ENC1=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/encrypt/$KEY_NAME" \
  -d "{\"plaintext\":\"$PLAINTEXT1_B64\"}" | jq -r .data.ciphertext)
echo "Ciphertext v1: ${ENC1:0:80}..."

# ---- Decrypt v1 (assert) ----
echo "== Decrypt v1 and assert round-trip =="
DEC1_B64=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/decrypt/$KEY_NAME" \
  -d "{\"ciphertext\":\"$ENC1\"}" | jq -r .data.plaintext)
[ "$DEC1_B64" = "$PLAINTEXT1_B64" ] || { echo "Round-trip v1 failed"; exit 1; }

# ---- Rotate -> latest ----
echo "== Rotate the key (creates new version) =="
curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/keys/$KEY_NAME/rotate" >/dev/null

LATEST=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  "$VAULT_ADDR/v1/transit/keys/$KEY_NAME" | jq -r .data.latest_version)
echo "Latest version after rotate: v$LATEST"

# ---- Encrypt with latest ----
echo "== Encrypt more data with latest version =="
PLAINTEXT2_B64=$(printf 'hello after rotation' | base64)
ENC2=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/encrypt/$KEY_NAME" \
  -d "{\"plaintext\":\"$PLAINTEXT2_B64\"}" | jq -r .data.ciphertext)
echo "Ciphertext v2: ${ENC2:0:80}..."

# ---- Decrypt v1 & v2 ----
echo "== Decrypt v1 and v2 after rotation (both should succeed) =="
DEC1_B64_AGAIN=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/decrypt/$KEY_NAME" \
  -d "{\"ciphertext\":\"$ENC1\"}" | jq -r .data.plaintext)
DEC2_B64=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/decrypt/$KEY_NAME" \
  -d "{\"ciphertext\":\"$ENC2\"}" | jq -r .data.plaintext)

[ "$DEC1_B64_AGAIN" = "$PLAINTEXT1_B64" ] || { echo "Decrypt v1 after rotate failed"; exit 1; }
[ "$DEC2_B64" = "$PLAINTEXT2_B64" ] || { echo "Decrypt v2 failed"; exit 1; }

# ---- Rewrap v1 -> latest ----
echo "== Rewrap v1 ciphertext to latest version =="
REWRAP_RAW=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/rewrap/$KEY_NAME" \
  -d "{\"ciphertext\":\"$ENC1\"}")
REWRAPPED=$(echo "$REWRAP_RAW" | jq -r .data.ciphertext)

# Fallback to batch if single returns null
if [ -z "$REWRAPPED" ] || [ "$REWRAPPED" = "null" ]; then
  RESP=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
    -X POST "$VAULT_ADDR/v1/transit/rewrap/$KEY_NAME" \
    -d "{\"batch_input\":[{\"ciphertext\":\"$ENC1\"}]}")
  REWRAPPED=$(echo "$RESP" | jq -r '.data.batch_results[0].ciphertext')
fi

if [ -z "$REWRAPPED" ] || [ "$REWRAPPED" = "null" ]; then
  echo "Rewrap failed. Raw response:" >&2
  echo "$REWRAP_RAW" | jq . >&2 || echo "$REWRAP_RAW" >&2
  exit 1
fi

echo "Rewrapped ciphertext: ${REWRAPPED:0:80}..."
REWRAP_VER=$(printf '%s' "$REWRAPPED" | awk -F: '{print $2}')
echo "Rewrapped version tag: $REWRAP_VER"

# ---- Decrypt rewrapped ----
echo "== Decrypt the rewrapped blob (should equal original v1 plaintext) =="
DEC_REWRAP_B64=$(curl -sS -H "X-Vault-Token: $VAULT_TOKEN" \
  -X POST "$VAULT_ADDR/v1/transit/decrypt/$KEY_NAME" \
  -d "{\"ciphertext\":\"$REWRAPPED\"}" | jq -r .data.plaintext)
[ "$DEC_REWRAP_B64" = "$PLAINTEXT1_B64" ] || { echo "Decrypt rewrapped failed"; exit 1; }

echo "== Success =="
echo "v1 ct: ${ENC1:0:80}..."
echo "v2 ct: ${ENC2:0:80}..."
echo "rewrapped ct: ${REWRAPPED:0:80}..."
