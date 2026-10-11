// Package keys holds the vault's keys at rest: the per-device key K_dev
// that encrypts a device's wrapped remote part, its seal in the vault's TPM
// (Sealer), and its copy under the vault recovery key (RecoveryKey).
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the size of K_dev and of the recovery key.
const KeySize = 32

// NewKey draws a K_dev.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Wipe overwrites a secret.
func Wipe(b []byte) { clear(b) }

// Encrypt is AES-256-GCM: nonce ‖ ciphertext ‖ tag.
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt opens what Encrypt made.
func Decrypt(key, sealed, aad []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	n := g.NonceSize()
	return g.Open(nil, sealed[:n], sealed[n:], aad)
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key of %d bytes, want %d", len(key), KeySize)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// RecoveryKey is the vault recovery key: 32 random bytes, shown once at
// init and kept offline. It is an X25519 private key; the vault keeps only
// its public key, and encrypts every K_dev to it (EncryptToRecovery), so
// that enrolment needs no recovery key and only the recovery key opens the
// copies.
type RecoveryKey [KeySize]byte

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewRecoveryKey draws a recovery key.
func NewRecoveryKey() (*RecoveryKey, error) {
	var k RecoveryKey
	if _, err := rand.Read(k[:]); err != nil {
		return nil, err
	}
	return &k, nil
}

// String is the key to write down: base32 in groups of four.
func (k *RecoveryKey) String() string {
	s := recoveryEncoding.EncodeToString(k[:])
	var groups []string
	for len(s) > 4 {
		groups = append(groups, s[:4])
		s = s[4:]
	}
	return strings.Join(append(groups, s), "-")
}

// ParseRecoveryKey reads a written-down key; case, spaces and dashes do
// not matter.
func ParseRecoveryKey(s string) (*RecoveryKey, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\n", "", "\r", "").Replace(s))
	b, err := recoveryEncoding.DecodeString(s)
	if err != nil || len(b) != KeySize {
		return nil, errors.New("this is not a recovery key: 52 letters and digits, in groups of four")
	}
	var k RecoveryKey
	copy(k[:], b)
	Wipe(b)
	return &k, nil
}

// Public is the key's X25519 public key, kept in the configuration.
func (k *RecoveryKey) Public() ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return nil, err
	}
	return priv.PublicKey().Bytes(), nil
}

// Wipe overwrites the key.
func (k *RecoveryKey) Wipe() { clear(k[:]) }

const recoveryInfo = "tpm2-kira-vault/recovery"

// EncryptToRecovery encrypts secret to the recovery key's public key:
// ephemeral X25519 public key (32 bytes) ‖ AES-256-GCM under
// HKDF-SHA256(shared secret, salt = ephemeral ‖ public).
func EncryptToRecovery(public, secret, aad []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return nil, fmt.Errorf("the recovery public key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, err
	}
	ephPub := eph.PublicKey().Bytes()
	key, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephPub...), public...), recoveryInfo, KeySize)
	Wipe(shared)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	ct, err := Encrypt(key, secret, aad)
	if err != nil {
		return nil, err
	}
	return append(ephPub, ct...), nil
}

// Open decrypts what EncryptToRecovery made.
func (k *RecoveryKey) Open(blob, aad []byte) ([]byte, error) {
	if len(blob) < 32 {
		return nil, errors.New("recovery copy too short")
	}
	priv, err := ecdh.X25519().NewPrivateKey(k[:])
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().NewPublicKey(blob[:32])
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, blob[:32]...), priv.PublicKey().Bytes()...), recoveryInfo, KeySize)
	Wipe(shared)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	return Decrypt(key, blob[32:], aad)
}
