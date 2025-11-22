package secure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// KeyPair bundles an ECDH keypair for establishing shared secrets.
type KeyPair struct {
	Private *ecdh.PrivateKey
	Public  []byte
}

// GenerateKeyPair returns a new Curve25519 keypair.
func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Private: private,
		Public:  private.PublicKey().Bytes(),
	}, nil
}

// ComputeShared returns a 32 byte shared key using the provided peer public key.
func ComputeShared(priv *ecdh.PrivateKey, peerPublic []byte) ([]byte, error) {
	curve := ecdh.X25519()
	key, err := curve.NewPublicKey(peerPublic)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(key)
}

// Encrypt uses AES-GCM with a random nonce and returns nonce+ciphertext.
func Encrypt(shared []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt reverses Encrypt and returns the plaintext.
func Decrypt(shared []byte, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(shared)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := sealed[:aead.NonceSize()]
	ciphertext := sealed[aead.NonceSize():]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// EncodeKey renders a public key as base64 for transport.
func EncodeKey(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

// DecodeKey parses a base64-encoded public key.
func DecodeKey(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// Fingerprint returns a short, colon separated SHA-256 fingerprint of the key.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	hexed := hex.EncodeToString(sum[:])
	parts := make([]string, 0, len(hexed)/2)
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, hexed[i:i+2])
	}
	return fmt.Sprintf("SHA256:%s", strings.Join(parts[:12], ":"))
}
