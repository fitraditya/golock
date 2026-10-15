package golock

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

// keySize is the required size, in bytes, of a golock encryption key.
// Ruby Lockbox uses a 32-byte (256-bit) key, hex-encoded to 64 characters.
const keySize = 32

// nonceSize is the size, in bytes, of the random nonce used for AES-256-GCM,
// confirmed against ankane/lockbox's Box#encrypt (SecureRandom.random_bytes(12),
// prepended to the ciphertext).
const nonceSize = 12

// encryptor implements single-key AES-256-GCM encryption/decryption.
//
// Wire layout: nonce (12 bytes) || ciphertext || tag (16 bytes), raw binary
// (no Base64) — this matches Ruby Lockbox's bare Box/Encryptor API exactly:
// Box#encrypt prepends a 12-byte random nonce to AES_GCM#encrypt's
// ciphertext||tag output, and only Base64-encodes when the caller passes
// encode: true (the ActiveRecord attribute layer's default, not the core
// Box API we're porting). There is no version/magic byte prefix. AAD is a
// plain caller-supplied byte string in both; see Box.Encrypt/Decrypt.
type encryptor struct {
	key []byte
}

func newEncryptor(key []byte) (*encryptor, error) {
	if len(key) != keySize {
		return nil, ErrInvalidKey
	}
	return &encryptor{key: key}, nil
}

// seal encrypts plaintext and returns nonce||ciphertext||tag. aad, if
// non-nil, is authenticated but not encrypted (must match on Decrypt).
func (e *encryptor) seal(plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	out := gcm.Seal(nonce, nonce, plaintext, aad)
	return out, nil
}

// open decrypts data produced by seal.
func (e *encryptor) open(data, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(data) < nonceSize+gcm.Overhead() {
		return nil, ErrCiphertextTooShort
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}
