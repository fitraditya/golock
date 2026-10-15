// Command golock-encrypt encrypts plaintext with a key, both given
// directly as command-line arguments, and prints the base64 ciphertext.
//
// Usage:
//
//	golock-encrypt <hex-key> <plaintext> [aad]
//
// The key must be a 64-character hex-encoded 32-byte key, as produced by
// Lockbox.generate_key / golock.GenerateKey.
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/fitraditya/golock"
)

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 {
		fmt.Fprintln(os.Stderr, "usage: golock-encrypt <hex-key> <plaintext> [aad]")
		os.Exit(2)
	}
	hexKey, plaintext := os.Args[1], os.Args[2]

	key, err := golock.DecodeKey(hexKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: decoding key:", err)
		os.Exit(1)
	}

	var opts []golock.Option
	if len(os.Args) == 4 {
		opts = append(opts, golock.WithAAD([]byte(os.Args[3])))
	}

	box, err := golock.New(key, opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: constructing box:", err)
		os.Exit(1)
	}

	ciphertext, err := box.Encrypt([]byte(plaintext))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: encrypt failed:", err)
		os.Exit(1)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(ciphertext))
}
