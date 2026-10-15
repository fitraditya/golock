package golock

import "errors"

// Sentinel errors returned by golock.
var (
	// ErrInvalidKey is returned when a provided key is missing, the wrong
	// length, or otherwise malformed.
	ErrInvalidKey = errors.New("golock: invalid key")

	// ErrNoKeys is returned by New when no keys were provided at all.
	ErrNoKeys = errors.New("golock: no keys provided")

	// ErrDecryptionFailed is returned when ciphertext could not be
	// decrypted/authenticated with any of the configured keys (wrong key,
	// tampered ciphertext, or corrupt data).
	ErrDecryptionFailed = errors.New("golock: decryption failed")

	// ErrCiphertextTooShort is returned when ciphertext is too short to
	// possibly contain a nonce and auth tag.
	ErrCiphertextTooShort = errors.New("golock: ciphertext too short")
)
