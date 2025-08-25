# Vault + Kyber (Post-Quantum KEM Prototype)

## What’s included
- Added support for **Kyber512, Kyber768, Kyber1024** key types in Vault Transit.
- Kyber used as **KEM** (key encapsulation mechanism).
- Derived secret expanded with **HKDF-SHA256**, then used with **AES-256-GCM** for data encryption/decryption.
- Key **rotation** supported.
- Integration tests for end-to-end encrypt/decrypt round-trip.

---

## Quick Start (local demo)

Clone my fork:
```bash
git clone https://github.com/igori0511/vault.git
cd vault
git checkout vault-CRYSTALS-Kyber
```
Bootstrap dependencies (first time only):
```bash
make bootstrap
```
```bash
make dev
```

```bash
./bin/vault server -dev -dev-root-token-id=root

export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root
```

# Ecnrypt/Decrypt flow
```bash
# default (768)
./enc_dec_flow.sh

# explicit sizes
./enc_dec_flow.sh 512
./enc_dec_flow.sh 768
./enc_dec_flow.sh 1024

# or via env
KEY_SIZE=1024 ./enc_dec_flow.sh
KEY_NAME="kyber-$(date +%s)" ./enc_dec_flow.sh 512

# sample output
 ./enc_dec_flow.sh 512
 
Using key name: my-kyber22
Using key type: kyber512
== Enable Transit ==
== Create Kyber key (my-kyber22, kyber512) ==
== Encrypt with Kyber, capture ciphertext ==
Ciphertext (CT): vault:v1:fP54+r1sqP/vCfisO5RM2/fl2zZjYmZtW3IhutejtSJGJzuKxCKpBVxAa7li3ypCjLwfh3N...
== Decrypt using captured CT ==
Decrypted (base64): aGVsbG8ga3liZXI=
Decoded: hello kyber
```

# Rotate/Rewrap flow
```bash
# default (768)
./rotate_rewrap_flow.sh

# specific sizes
./rotate_rewrap_flow.sh 512
./rotate_rewrap_flow.sh 768
./rotate_rewrap_flow.sh 1024

# custom key name
KEY_NAME="kyber-$(date +%s)" ./rotate_rewrap_flow.sh 512

# sample output
./rotate_rewrap_flow.sh 512

Using key name: test-kyber
Using key type: kyber512
== Enable Transit (idempotent) ==
== Create Kyber key (test-kyber, kyber512) ==
== Encrypt some data with version 1 ==
Ciphertext v1: vault:v1:ZFWEHyEXzhos1hFrA7dkhcGjF6vC0K9YklUk1dYtLNFJ3vTXmDxjHz3ItF5znADNyiVP2cp...
== Decrypt v1 and assert round-trip ==
== Rotate the key (creates new version) ==
Latest version after rotate: v2
== Encrypt more data with latest version ==
Ciphertext v2: vault:v2:++vkJmCAIeZonLp4J5UMZz2UUZi3anj+ZiYQ/YKMKXYTwrGhMJKQha7yv9CLv1JRcb2RBRj...
== Decrypt v1 and v2 after rotation (both should succeed) ==
== Rewrap v1 ciphertext to latest version ==
Rewrapped ciphertext: vault:v2:oXGcrIaQCap+2fXpoPeQI9o9beFxtIAklH6nc+Lt8M3YchsEQkwnDnFA/dIyPCfufX5Q1I5...
Rewrapped version tag: v2
== Decrypt the rewrapped blob (should equal original v1 plaintext) ==
== Success ==
v1 ct: vault:v1:ZFWEHyEXzhos1hFrA7dkhcGjF6vC0K9YklUk1dYtLNFJ3vTXmDxjHz3ItF5znADNyiVP2cp...
v2 ct: vault:v2:++vkJmCAIeZonLp4J5UMZz2UUZi3anj+ZiYQ/YKMKXYTwrGhMJKQha7yv9CLv1JRcb2RBRj...
rewrapped ct: vault:v2:oXGcrIaQCap+2fXpoPeQI9o9beFxtIAklH6nc+Lt8M3YchsEQkwnDnFA/dIyPCfufX5Q1I5...
```

# Testing
```bash
make test # runs tests for all components, but the docker image isn't native to linux and fails.

make test TEST=./builtin/logical/transit/...
```