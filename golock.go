// Package golock is a Go port of the Ruby gem "Lockbox"
// (https://github.com/ankane/lockbox), a library for encrypting data at
// rest (e.g. database column/attribute-level encryption).
//
// Wire-format compatibility: this package implements the same AES-256-GCM
// "aes-gcm" Box format as Ruby Lockbox's bare Box/Encryptor API (the
// default box type since early 0.x, unchanged through 1.x — verified
// against the real gem at both v1.0.0 and v1.4.1): a 32-byte key,
// a random 12-byte nonce prepended to the AES-256-GCM output
// (nonce||ciphertext||tag, 16-byte tag), raw binary (no Base64) unless the
// caller encodes it themselves, and associated data (AAD) support
// matching Ruby's v1.4.1 Box API: per-call via EncryptWithAAD/
// DecryptWithAAD, or a Box-level default via WithAAD (ported from gem
// v1.2.0's Box.new(associated_data:) option). Ciphertexts produced by
// this package should be byte-for-byte interoperable with Ruby's
// Lockbox::Box#encrypt/#decrypt given the same raw key and AAD.
//
// Not ported: Ruby Lockbox's ActiveRecord attribute integration (and its
// encode_attributes-by-default behavior), optional PKCS7 padding, the
// xchacha20/xsalsa20/hybrid box types, and real KMS provider
// implementations (kms.go only defines the KeyProvider interface).
//
// Basic usage:
//
//	key, err := golock.GenerateKey()
//	box, err := golock.New(mustDecode(key))
//	ciphertext, err := box.Encrypt([]byte("plaintext"))
//	plaintext, err := box.Decrypt(ciphertext)
package golock

import (
	"crypto/rand"
	"encoding/hex"
)

// Box encrypts and decrypts data using AES-256-GCM, optionally trying
// multiple keys on decrypt to support key rotation.
type Box struct {
	// encryptors[0] is the primary key, used for all encryption and tried
	// first on decryption. Any additional entries (added via WithKey /
	// WithHexKey) are only used on decryption, in order.
	encryptors []*encryptor

	// defaultAAD is used by Encrypt/Decrypt when no explicit associated
	// data is given, matching Ruby Lockbox's Box.new(associated_data:)
	// default (added in gem v1.2.0; present in the v1.4.1 version this
	// package targets). It is nil unless set via WithAAD. An explicit
	// call to EncryptWithAAD/DecryptWithAAD always overrides this default
	// (even with nil), the same way Ruby's Box#encrypt/#decrypt treat an
	// explicitly-passed associated_data: differently from an omitted one.
	defaultAAD []byte
}

// New creates a Box using key as the primary (encryption) key. key
// must be a raw 32-byte AES-256 key; use DecodeKey to decode a
// hex-encoded key such as one produced by GenerateKey.
//
// Additional keys for rotation support may be supplied via WithKey or
// WithHexKey; they are consulted (in order, after the primary key) when
// decrypting, but never used to encrypt. A default associated-data value
// may be supplied via WithAAD.
func New(key []byte, opts ...Option) (*Box, error) {
	if len(key) == 0 {
		return nil, ErrNoKeys
	}

	primary, err := newEncryptor(key)
	if err != nil {
		return nil, err
	}

	l := &Box{encryptors: []*encryptor{primary}}

	for _, opt := range opts {
		if err := opt(l); err != nil {
			return nil, err
		}
	}

	return l, nil
}

// Encrypt encrypts plaintext using the primary key, returning
// nonce||ciphertext||tag (raw binary, matching Ruby Lockbox's bare Box
// API). This is equivalent to calling EncryptWithAAD(plaintext, aad),
// where aad is the Box's default associated data (nil unless set via
// WithAAD) — mirroring Ruby's Box#encrypt falling back to the
// associated_data given to Box.new when none is passed per call.
func (l *Box) Encrypt(plaintext []byte) ([]byte, error) {
	return l.EncryptWithAAD(plaintext, l.defaultAAD)
}

// EncryptWithAAD is like Encrypt, but explicitly sets aad (associated
// data), overriding the Box's default (if any): aad is not encrypted or
// included in the output, but the same aad must be passed to
// DecryptWithAAD (or be the Box's default, via Decrypt) or decryption
// will fail. This matches Ruby Lockbox's per-call associated_data option
// on Box#encrypt.
func (l *Box) EncryptWithAAD(plaintext, aad []byte) ([]byte, error) {
	return l.encryptors[0].seal(plaintext, aad)
}

// Decrypt decrypts ciphertext using the Box's default associated data
// (nil unless set via WithAAD); equivalent to
// DecryptWithAAD(ciphertext, aad) with that default.
func (l *Box) Decrypt(ciphertext []byte) ([]byte, error) {
	return l.DecryptWithAAD(ciphertext, l.defaultAAD)
}

// DecryptWithAAD decrypts ciphertext, trying each configured key in order
// (primary key first, then any rotation keys added via WithKey /
// WithHexKey) until one succeeds, authenticating aad in the process (it
// must match what was passed to EncryptWithAAD). Returns
// ErrDecryptionFailed if no key can decrypt/authenticate the ciphertext.
func (l *Box) DecryptWithAAD(ciphertext, aad []byte) ([]byte, error) {
	var lastErr error = ErrDecryptionFailed
	for _, enc := range l.encryptors {
		plaintext, err := enc.open(ciphertext, aad)
		if err == nil {
			return plaintext, nil
		}
		if err != ErrDecryptionFailed {
			// e.g. ErrCiphertextTooShort - no point trying further keys.
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// GenerateKey generates a random 32-byte (256-bit) key and returns it
// hex-encoded (64 hex characters), matching Ruby's Lockbox.generate_key.
func GenerateKey() (string, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// DecodeKey decodes a hex-encoded key (as produced by GenerateKey) into
// raw bytes suitable for passing to New or WithKey. Returns ErrInvalidKey
// if hexKey is not valid hex or does not decode to 32 bytes.
func DecodeKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, ErrInvalidKey
	}
	if len(key) != keySize {
		return nil, ErrInvalidKey
	}
	return key, nil
}
