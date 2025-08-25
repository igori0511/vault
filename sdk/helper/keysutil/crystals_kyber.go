// Package keysutil provides Kyber-based KEM→DEM utilities used by Transit.
// This module implements a KEM-DEM construction:
//  1. A Kyber KEM (via Cloudflare CIRCL) produces a shared secret and a
//     ciphertext "capsule" that hides the ephemeral KEM key material.
//  2. That shared secret is expanded with HKDF-SHA256 into a 32-byte key
//     for the DEM (AES-256-GCM). Associated data (AD) is bound via AEAD.
//
// Security notes:
//   - Errors during decryption are intentionally opaque ("decryption failed")
//     to avoid building padding/oracle side channels.
//   - AD is canonicalized so that nil and empty are treated identically.
//   - The HKDF "info" includes a versioned label and hashes of the capsule
//     and AD; the salt is H(capsule). This binds the DEM key to the exact
//     KEM ciphertext and to the protocol version, reducing cross-protocol
//     reuse risk.
//   - Sensitive material (KEM shared secret, derived DEM key) is wiped from
//     memory after use.
//
// Implementation relies on Cloudflare CIRCL's kyber{512,768,1024} Schemes.
// The chosen Kyber variant is controlled by KeyType.
package keysutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/hashicorp/vault/sdk/helper/errutil"
	"golang.org/x/crypto/hkdf"
)

// kyberBox is a small helper that bundles a specific Kyber scheme (512/768/1024)
// with a versioned HKDF label. The label lets us evolve the construction without
// key/AD collisions across versions.
type kyberBox struct {
	s     kem.Scheme // concrete Kyber variant implementation
	label string     // protocol label used in HKDF 'info' (versioned)
}

// labelFor returns the protocol label used as part of HKDF 'info'.
// It encodes the Kyber variant and the DEM algorithm+version. Bumping
// this label (e.g., "-v2") is the mechanism for safe, explicit upgrades.
func labelFor(kt KeyType) string {
	return kt.String() + "-aes256-gcm-v1" // e.g. "kyber512-aes256-gcm-v1"
}

// newKyberBox selects the appropriate CIRCL Kyber scheme based on KeyType.
//
// On success, the returned kyberBox is ready to perform encapsulation/
// decapsulation and DEM key derivation with a versioned HKDF label.
func newKyberBox(t KeyType) (kyberBox, error) {
	switch t {
	case KeyType_Kyber512:
		return kyberBox{s: kyber512.Scheme(), label: labelFor(t)}, nil
	case KeyType_Kyber768:
		return kyberBox{s: kyber768.Scheme(), label: labelFor(t)}, nil
	case KeyType_Kyber1024:
		return kyberBox{s: kyber1024.Scheme(), label: labelFor(t)}, nil
	default:
		// Internal error used within Vault code paths; callers treat this as non-user input.
		return kyberBox{}, errutil.InternalError{Err: "unsupported Kyber key type"}
	}
}

// Encrypt performs KEM-DEM encryption:
//  1. Encapsulate with the recipient's Kyber public key → (capsule, shared secret).
//  2. Derive a 32-byte AES-256 key from the shared secret via HKDF-SHA256, with
//     salt/info bound to the capsule and AD.
//  3. Generate a random nonce and encrypt plaintext with AES-256-GCM, authenticating AD.
//
// Returns the KEM capsule, the AEAD nonce, and the ciphertext.
func (k kyberBox) Encrypt(pk kem.PublicKey, plaintext, ad []byte) (capsule, nonce, ciphertext []byte, err error) {
	// Canonicalize AD so both nil and empty slice yield the same AEAD tag.
	if len(ad) == 0 {
		ad = nil
	}

	// Kyber encapsulation: produces the receiver-verifiable "capsule" and a shared secret.
	capsule, ss, err := k.s.Encapsulate(pk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encapsulate: %w", err)
	}
	defer wipe(ss) // Best-effort zeroization of secret material.

	// HKDF expand into a 32-byte AES-256 key; bind to capsule and AD.
	key, err := k.deriveAES256Key(ss, capsule, ad)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive key: %w", err)
	}
	defer wipe(key)

	// Initialize AEAD and create a fresh, random nonce of the correct size.
	aead, n, err := k.newGCMWithNonce(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("gcm init: %w", err)
	}

	// Seal authenticates AD and encrypts the plaintext.
	nonce = n
	ciphertext = aead.Seal(nil, nonce, plaintext, ad)
	return capsule, nonce, ciphertext, nil
}

// Decrypt performs the inverse of Encrypt:
//  1. Quick structural checks (capsule size, nonce length later).
//  2. Decapsulate with the recipient's Kyber private key to recover the shared secret.
//  3. Derive the same AES-256 key from (secret, capsule, AD).
//  4. Open the AEAD with AD; return plaintext on success.
//
// All errors are mapped to a uniform "decryption failed" to prevent
// distinguishers that could form a decryption oracle.
func (k kyberBox) Decrypt(sk kem.PrivateKey, capsule, nonce, ciphertext, ad []byte) ([]byte, error) {
	// Canonicalize AD so nil == empty for AEAD/HKDF.
	if len(ad) == 0 {
		ad = nil
	}

	// Opaque failures to avoid oracles; also precheck capsule length.
	if len(capsule) != k.s.CiphertextSize() {
		return nil, errors.New("decryption failed")
	}

	// KEM decapsulation → recover the shared secret for this capsule.
	ss, err := k.s.Decapsulate(sk, capsule)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	defer wipe(ss)

	// Derive the DEM key deterministically from (secret, capsule, AD).
	key, err := k.deriveAES256Key(ss, capsule, ad)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	defer wipe(key)

	// Reconstruct AEAD and validate nonce size before decryption.
	aead, err := k.newGCM(key)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("decryption failed")
	}

	// Open authenticates AD and decrypts. Error remains opaque.
	pt, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	return pt, nil
}

// deriveAES256Key expands the KEM shared secret into a 32-byte DEM key using HKDF-SHA256.
//
// Context binding & versioning (domain separation):
//
//	info = label || H(capsule) || H(associated_data)
//	salt = H(capsule)
//
// Rationale:
//   - H(capsule) in both 'salt' and 'info' ties the symmetric key to the exact
//     Kyber ciphertext, preventing accidental key reuse across different KEM
//     contexts/protocols.
//   - Including H(AD) in 'info' ensures the same (secret,capsule) yields different
//     DEM keys when the caller varies AD; this strengthens misuse resistance.
//   - 'label' carries the Kyber variant and the DEM/version; changing it safely
//     rotates derived keys for the same inputs.
func (k kyberBox) deriveAES256Key(secret, capsule, ad []byte) ([]byte, error) {
	hc := sha256.Sum256(capsule)
	ha := sha256.Sum256(ad)
	info := append(append([]byte(k.label), hc[:]...), ha[:]...)

	// Salt with H(capsule) to harden against cross-protocol key reuse.
	salt := hc[:]

	h := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, 32) // AES-256 key size
	_, err := io.ReadFull(h, key)
	return key, err
}

// newGCMWithNonce constructs an AES-256-GCM AEAD from 'key' and returns a freshly
// generated random nonce of the correct size. The nonce must be unique per key.
func (k kyberBox) newGCMWithNonce(key []byte) (cipher.AEAD, []byte, error) {
	aead, err := k.newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("rand nonce: %w", err)
	}
	return aead, nonce, nil
}

// newGCM wraps the provided 32-byte key into an AES-256 block cipher and constructs
// a GCM AEAD. The caller is responsible for nonce management.
func (k kyberBox) newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return aead, nil
}

// wipe zeroes sensitive byte slices in place. This is a best-effort measure;
// the Go compiler/runtime may copy data during optimization, so absolute
// guarantees are not possible. Still, this reduces the lifetime of secrets.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
