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

type kyberBox struct {
	s     kem.Scheme
	label string
}

func labelFor(kt KeyType) string {
	return kt.String() + "-aes256-gcm-v1" // "kyber512-aes256-gcm-v1", etc.
}

func newKyberBox(t KeyType) (kyberBox, error) {
	switch t {
	case KeyType_Kyber512:
		return kyberBox{s: kyber512.Scheme(), label: labelFor(t)}, nil
	case KeyType_Kyber768:
		return kyberBox{s: kyber768.Scheme(), label: labelFor(t)}, nil
	case KeyType_Kyber1024:
		return kyberBox{s: kyber1024.Scheme(), label: labelFor(t)}, nil
	default:
		return kyberBox{}, errutil.InternalError{Err: "unsupported Kyber key type"}
	}
}

func (k kyberBox) Encrypt(pk kem.PublicKey, plaintext, ad []byte) (capsule, nonce, ciphertext []byte, err error) {
	if len(ad) == 0 {
		ad = nil
	}

	capsule, ss, err := k.s.Encapsulate(pk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encapsulate: %w", err)
	}
	defer wipe(ss)

	key, err := k.deriveAES256Key(ss, capsule, ad) // salted KDF (current)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive key: %w", err)
	}
	defer wipe(key)

	aead, n, err := k.newGCMWithNonce(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("gcm init: %w", err)
	}

	nonce = n
	ciphertext = aead.Seal(nil, nonce, plaintext, ad)
	return capsule, nonce, ciphertext, nil
}

func (k kyberBox) Decrypt(sk kem.PrivateKey, capsule, nonce, ciphertext, ad []byte) ([]byte, error) {
	// Canonicalize AAD so nil == empty for AEAD/HKDF.
	if len(ad) == 0 {
		ad = nil
	}

	// Opaque failures to avoid oracles.
	if len(capsule) != k.s.CiphertextSize() {
		return nil, errors.New("decryption failed")
	}

	// KEM decapsulation → shared secret.
	ss, err := k.s.Decapsulate(sk, capsule)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	defer wipe(ss)

	// Derive DEM key (salted HKDF bound to capsule).
	key, err := k.deriveAES256Key(ss, capsule, ad)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	defer wipe(key)

	// AEAD (AES-256-GCM) and nonce check.
	aead, err := k.newGCM(key)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	if len(nonce) != aead.NonceSize() {
		return nil, errors.New("decryption failed")
	}

	// Open with AD; keep error opaque.
	pt, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, errors.New("decryption failed")
	}
	return pt, nil
}

// deriveAES256Key derives the DEM key with HKDF-SHA256.
// Context binding:
//
//	info = label || H(capsule) || H(associated_data)
//	salt = H(capsule)   // current scheme, resists cross-protocol key reuse
func (k kyberBox) deriveAES256Key(secret, capsule, ad []byte) ([]byte, error) {
	hc := sha256.Sum256(capsule)
	ha := sha256.Sum256(ad)
	info := append(append([]byte(k.label), hc[:]...), ha[:]...)

	// Salt with H(capsule) to harden against cross-protocol key reuse.
	salt := hc[:]

	h := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, 32)
	_, err := io.ReadFull(h, key)
	return key, err
}

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

// wipe zeroes sensitive byte slices in place.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
