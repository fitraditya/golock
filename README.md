# golock

A Go port of the Ruby gem [Lockbox](https://github.com/ankane/lockbox) — a
library for encrypting data at rest (e.g. database column/attribute-level
encryption).

**Wire-format compatible** with Ruby Lockbox's bare `Box`/`Encryptor` API
(the default `aes-gcm` box type, unchanged from early 0.x through 1.x —
verified by decrypting real ciphertext from both gem v1.0.0 and **v1.4.1**
in `golock_test.go`'s `TestRubyLockboxInterop`): a 32-byte AES-256 key, a
random 12-byte nonce prepended to the AES-GCM output
(`nonce || ciphertext || tag`, 16-byte tag), raw binary output (no Base64
unless you add it yourself), and associated data (AAD) support matching
Ruby. Given the same raw key (and AAD, if used), ciphertext is
interchangeable between this library and `Lockbox::Box#encrypt`/`#decrypt`
in Ruby.

## Install

```bash
go get github.com/fitraditya/golock
```

Requires Go 1.25+ (see `go.mod`). No external dependencies — standard
library only.

## Usage

```go
package main

import (
	"fmt"
	"log"

	"github.com/fitraditya/golock"
)

func main() {
	// Generate a new random key (hex-encoded, like Lockbox.generate_key in Ruby).
	hexKey, err := golock.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	key, err := golock.DecodeKey(hexKey)
	if err != nil {
		log.Fatal(err)
	}

	box, err := golock.New(key)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := box.Encrypt([]byte("plaintext"))
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := box.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(plaintext)) // "plaintext"
}
```

This maps onto Ruby Lockbox's core (non-Rails) API:

| Ruby                        | Go                        |
| ---------------------------- | -------------------------- |
| `Lockbox.generate_key`       | `golock.GenerateKey()`     |
| `Lockbox.new(key: key)`      | `golock.New(key)`          |
| `box.encrypt(plaintext)`     | `box.Encrypt(plaintext)`   |
| `box.decrypt(ciphertext)`    | `box.Decrypt(ciphertext)`  |

### Key rotation

Like Ruby Lockbox, `golock` supports trying multiple keys on decrypt while
always encrypting with a single primary key:

```go
box, err := golock.New(newKey, golock.WithKey(oldKey))
// box.Encrypt always uses newKey.
// box.Decrypt tries newKey, then oldKey.
```

`WithHexKey` is also available for hex-encoded rotation keys.

### Associated data (AAD)

`EncryptWithAAD`/`DecryptWithAAD` authenticate (but do not encrypt) extra
context, matching Ruby Lockbox's per-call `associated_data:` option:

```go
ciphertext, err := box.EncryptWithAAD([]byte("plaintext"), []byte("users:email"))
plaintext, err := box.DecryptWithAAD(ciphertext, []byte("users:email"))
// Decrypting with different (or missing) AAD fails with ErrDecryptionFailed.
```

`WithAAD` sets a default AAD at construction time, matching Ruby's
`Lockbox.new(key:, associated_data:)` (gem v1.2.0+, present in the v1.4.1
version this package targets). `Encrypt`/`Decrypt` then use that default
automatically; `EncryptWithAAD`/`DecryptWithAAD` still override it per
call, even with `nil`:

```go
box, err := golock.New(key, golock.WithAAD([]byte("users:email")))
ciphertext, err := box.Encrypt([]byte("plaintext"))  // uses the default AAD
plaintext, err := box.Decrypt(ciphertext)             // uses the default AAD
```

### Errors

See `errors.go` for sentinel errors: `ErrInvalidKey`, `ErrNoKeys`,
`ErrDecryptionFailed`, `ErrCiphertextTooShort`.

## What's missing compared to Ruby Lockbox

Deliberately out of scope so far — `golock` only ports the core
`Box`/`Encryptor` encryption API, not the Rails/framework integrations or
the alternate crypto backends:

| Ruby Lockbox feature | Status |
| --- | --- |
| ActiveRecord attribute encryption (`has_encrypted`) | Not ported — no ORM integration; use `Box`/`golock.New` directly |
| `encode_attributes` (Base64-by-default at the attribute layer) | Not ported — `golock` always outputs raw binary; encode it yourself if needed |
| PKCS7 padding (`padding: true`) | Not ported |
| `xchacha20` / `xsalsa20` / `hybrid` box types (libsodium-based) | Not ported — AES-256-GCM only |
| KMS-backed key wrapping (AWS KMS, Google Cloud KMS, Azure Key Vault, Vault) | Stub only — `kms.go` defines a `KeyProvider` interface but has no concrete provider implementations |
| ActiveStorage / CarrierWave file-attachment encryption | Not ported |
| Key rotation via `previous_versions:` (incl. skipping KMS `master_key:` entries) | Partially ported — `WithKey`/`WithHexKey` give the same decrypt-tries-each-key behavior for plain keys; no KMS-wrapped rotation keys since KMS isn't implemented |
| Associated data (`associated_data:`), per-call and Box-level default | Ported — `EncryptWithAAD`/`DecryptWithAAD`, `WithAAD` |
| `Lockbox.generate_key` | Ported — `golock.GenerateKey()` |

## Sample CLIs (`samples/`)

`samples/golock-encrypt` and `samples/golock-decrypt` are standalone,
self-contained programs (no shared code between them, no file I/O) for
exercising `golock` from the command line. Key, plaintext/ciphertext, and
an optional AAD are all passed directly as arguments; ciphertext is
base64.

```bash
go build -o golock-encrypt ./samples/golock-encrypt
go build -o golock-decrypt ./samples/golock-decrypt

./golock-encrypt <hex-key> <plaintext> [aad]
./golock-decrypt <hex-key> <base64-ciphertext> [aad]

# e.g. (KEY is a 64-char hex key, e.g. from golock.GenerateKey — see Usage above)
CT=$(./golock-encrypt "$KEY" "hello world")
./golock-decrypt "$KEY" "$CT"

./golock-encrypt "$KEY" "hello with context" "users:email"
./golock-decrypt "$KEY" "$CT_WITH_AAD" "users:email"
```

Note: since the key is a plain argument, it lands in shell history and
process listings — fine for local experiments with test keys, but avoid
this for real production keys.

## Development

```bash
go build ./...
go vet ./...
go test ./...
```
