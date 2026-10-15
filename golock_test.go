package golock

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	hexKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	key, err := DecodeKey(hexKey)
	if err != nil {
		t.Fatalf("DecodeKey() error = %v", err)
	}
	return key
}

func TestGenerateKey(t *testing.T) {
	hexKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if len(hexKey) != keySize*2 {
		t.Errorf("GenerateKey() length = %d, want %d", len(hexKey), keySize*2)
	}
	key, err := DecodeKey(hexKey)
	if err != nil {
		t.Fatalf("DecodeKey() error = %v", err)
	}
	if len(key) != keySize {
		t.Errorf("DecodeKey() length = %d, want %d", len(key), keySize)
	}

	// Two generated keys should (overwhelmingly likely) differ.
	hexKey2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if hexKey == hexKey2 {
		t.Errorf("GenerateKey() produced identical keys on successive calls")
	}
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty", []byte("")},
		{"short", []byte("hi")},
		{"sentence", []byte("the quick brown fox jumps over the lazy dog")},
		{"binary", []byte{0x00, 0x01, 0xFF, 0xFE, 0x10, 0x20}},
		{"unicode", []byte("héllo wörld 日本語")},
	}

	key := mustKey(t)
	box, err := New(key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := box.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}
			if bytes.Equal(ciphertext, tt.plaintext) {
				t.Errorf("Encrypt() returned plaintext unchanged")
			}

			plaintext, err := box.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if !bytes.Equal(plaintext, tt.plaintext) {
				t.Errorf("Decrypt() = %q, want %q", plaintext, tt.plaintext)
			}
		})
	}
}

func TestEncryptNonDeterministic(t *testing.T) {
	key := mustKey(t)
	box, err := New(key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	plaintext := []byte("same plaintext")
	c1, err := box.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	c2, err := box.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if bytes.Equal(c1, c2) {
		t.Errorf("Encrypt() produced identical ciphertexts for repeated calls (nonce reuse?)")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	box1, err := New(mustKey(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	box2, err := New(mustKey(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ciphertext, err := box1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	if _, err := box2.Decrypt(ciphertext); err == nil {
		t.Errorf("Decrypt() with wrong key succeeded, want error")
	} else if err != ErrDecryptionFailed {
		t.Errorf("Decrypt() error = %v, want ErrDecryptionFailed", err)
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	box, err := New(mustKey(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ciphertext, err := box.Encrypt([]byte("secret message"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	// Flip a bit in the last byte (part of the GCM auth tag).
	tampered[len(tampered)-1] ^= 0x01

	if _, err := box.Decrypt(tampered); err == nil {
		t.Errorf("Decrypt() with tampered ciphertext succeeded, want error")
	} else if err != ErrDecryptionFailed {
		t.Errorf("Decrypt() error = %v, want ErrDecryptionFailed", err)
	}
}

func TestDecryptTruncatedCiphertextFails(t *testing.T) {
	box, err := New(mustKey(t))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := box.Decrypt([]byte("short")); err == nil {
		t.Errorf("Decrypt() with truncated ciphertext succeeded, want error")
	}
}

func TestNewInvalidKey(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Errorf("New(nil) succeeded, want error")
	}
	if _, err := New([]byte("too-short")); err != ErrInvalidKey {
		t.Errorf("New(short key) error = %v, want ErrInvalidKey", err)
	}
}

func TestKeyRotation(t *testing.T) {
	oldKey := mustKey(t)
	newKey := mustKey(t)

	// Encrypt with the old key only.
	oldBox, err := New(oldKey)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ciphertext, err := oldBox.Encrypt([]byte("legacy data"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// A box configured with newKey as primary and oldKey as a rotation
	// key should still decrypt data encrypted under oldKey...
	rotatingBox, err := New(newKey, WithKey(oldKey))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	plaintext, err := rotatingBox.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(plaintext) != "legacy data" {
		t.Errorf("Decrypt() = %q, want %q", plaintext, "legacy data")
	}

	// ...but Encrypt() must always use the primary (new) key.
	newCiphertext, err := rotatingBox.Encrypt([]byte("fresh data"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if _, err := oldBox.Decrypt(newCiphertext); err == nil {
		t.Errorf("old-key-only box decrypted data encrypted with new primary key")
	}
	newOnlyBox, err := New(newKey)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := newOnlyBox.Decrypt(newCiphertext); err != nil {
		t.Errorf("Decrypt() with new key error = %v", err)
	}
}

// TestRubyLockboxInterop decrypts fixed ciphertexts produced by the real
// Ruby `lockbox` gem with the all-zeros 32-byte key, confirming this
// package is byte-for-byte wire-compatible with Ruby's
// Lockbox::Box#encrypt/#decrypt. Vectors were cross-checked against both
// lockbox 1.0.0 and 1.4.1 (running under Ruby 2.6.3): lib/lockbox/aes_gcm.rb
// is byte-identical between those versions, and box.rb's only functional
// change in that range is accepting associated_data: as a Box.new default
// in addition to a per-call option — the wire format (key size, nonce
// size/placement, tag size, AAD semantics) is unchanged. Vectors were
// generated with:
//
//	gem install lockbox -v 1.0.0
//	key_bin = ["0"*64].pack("H*")
//	box = Lockbox.new(key: key_bin)
//	box.encrypt("plaintext")                                  # => basic
//	box.encrypt("plaintext", associated_data: "users:email")  # => AAD
func TestRubyLockboxInterop(t *testing.T) {
	key, err := DecodeKey("0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("DecodeKey() error = %v", err)
	}
	box, err := New(key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Run("basic", func(t *testing.T) {
		ciphertext := mustHexDecode(t, "2e90bdc1d4ed2878e96c49e11be052fefca32f250bc6f9084668d40e7696dfa2678161ebf3")
		plaintext, err := box.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if string(plaintext) != "plaintext" {
			t.Errorf("Decrypt() = %q, want %q", plaintext, "plaintext")
		}
	})

	t.Run("aad", func(t *testing.T) {
		ciphertext := mustHexDecode(t, "c5b187ef61d87456528e5e6026b8df6a194151d4fe9a664a680e6d4289ae1e5372d9338d3e")
		aad := []byte("users:email")

		plaintext, err := box.DecryptWithAAD(ciphertext, aad)
		if err != nil {
			t.Fatalf("DecryptWithAAD() error = %v", err)
		}
		if string(plaintext) != "plaintext" {
			t.Errorf("DecryptWithAAD() = %q, want %q", plaintext, "plaintext")
		}

		// Ruby's gem rejects this same ciphertext when AAD is omitted
		// (Lockbox::DecryptionError); we must match that behavior.
		if _, err := box.Decrypt(ciphertext); err != ErrDecryptionFailed {
			t.Errorf("Decrypt() without AAD error = %v, want ErrDecryptionFailed", err)
		}
	})

	t.Run("empty_plaintext", func(t *testing.T) {
		ciphertext := mustHexDecode(t, "c696fe34237701ff69d30c5a3146398f84f2141c886495a217382adf")
		plaintext, err := box.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if len(plaintext) != 0 {
			t.Errorf("Decrypt() = %q, want empty", plaintext)
		}
	})

	// Same key/plaintext/AAD, but this vector was generated against
	// lockbox 1.4.1 specifically (gem "lockbox", "1.4.1"), not 1.0.0.
	t.Run("aad_v1_4_1", func(t *testing.T) {
		ciphertext := mustHexDecode(t, "4cbff0c0c49b79b3e63acaa36e4b3100486d249638a1ebce80a6fd638c7e546c405dde6925")
		aad := []byte("users:email")

		plaintext, err := box.DecryptWithAAD(ciphertext, aad)
		if err != nil {
			t.Fatalf("DecryptWithAAD() error = %v", err)
		}
		if string(plaintext) != "plaintext" {
			t.Errorf("DecryptWithAAD() = %q, want %q", plaintext, "plaintext")
		}
	})

	// Generated with Lockbox.new(key: key_bin, associated_data: "users:email")
	// (gem v1.4.1) — box-level default associated_data, not passed per call.
	// WithAAD must reproduce this: Decrypt() (no explicit AAD) falls back
	// to the Box's default.
	t.Run("default_aad_v1_4_1", func(t *testing.T) {
		ciphertext := mustHexDecode(t, "29bd1e250e6715a0a1eb215e276e06d423e68f4d78522e7f893a4a9977f0342d966821d423")
		aad := []byte("users:email")

		aadBox, err := New(key, WithAAD(aad))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		plaintext, err := aadBox.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() error = %v", err)
		}
		if string(plaintext) != "plaintext" {
			t.Errorf("Decrypt() = %q, want %q", plaintext, "plaintext")
		}

		// Ruby: explicitly passing associated_data: nil per call overrides
		// the Box-level default and fails (Lockbox::DecryptionError). Our
		// DecryptWithAAD(ciphertext, nil) must match that.
		if _, err := aadBox.DecryptWithAAD(ciphertext, nil); err != ErrDecryptionFailed {
			t.Errorf("DecryptWithAAD() with explicit nil AAD error = %v, want ErrDecryptionFailed", err)
		}
	})
}

// TestWithAAD exercises the Box-level default associated data option
// end-to-end using this package's own Encrypt/Decrypt (not fixed Ruby
// vectors; see TestRubyLockboxInterop/default_aad_v1_4_1 for that).
func TestWithAAD(t *testing.T) {
	key := mustKey(t)
	aad := []byte("users:email")

	box, err := New(key, WithAAD(aad))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ciphertext, err := box.Encrypt([]byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Decrypt() (no explicit AAD) uses the Box's default and succeeds.
	plaintext, err := box.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if string(plaintext) != "plaintext" {
		t.Errorf("Decrypt() = %q, want %q", plaintext, "plaintext")
	}

	// Explicit AAD matching the default also works.
	if _, err := box.DecryptWithAAD(ciphertext, aad); err != nil {
		t.Errorf("DecryptWithAAD() with matching explicit AAD error = %v", err)
	}

	// Explicit nil AAD overrides (and therefore mismatches) the default.
	if _, err := box.DecryptWithAAD(ciphertext, nil); err != ErrDecryptionFailed {
		t.Errorf("DecryptWithAAD() with nil AAD error = %v, want ErrDecryptionFailed", err)
	}

	// A box with no WithAAD option has a nil default and cannot decrypt
	// ciphertext that was authenticated against a non-nil default.
	plainBox, err := New(key)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := plainBox.Decrypt(ciphertext); err != ErrDecryptionFailed {
		t.Errorf("Decrypt() without default AAD error = %v, want ErrDecryptionFailed", err)
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) error = %v", s, err)
	}
	return b
}

func TestWithHexKey(t *testing.T) {
	oldHexKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	oldKey, err := DecodeKey(oldHexKey)
	if err != nil {
		t.Fatalf("DecodeKey() error = %v", err)
	}
	oldBox, err := New(oldKey)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ciphertext, err := oldBox.Encrypt([]byte("data"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	box, err := New(mustKey(t), WithHexKey(oldHexKey))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := box.Decrypt(ciphertext); err != nil {
		t.Errorf("Decrypt() error = %v", err)
	}
}
