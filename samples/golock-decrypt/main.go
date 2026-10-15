// Command golock-decrypt decrypts base64 ciphertext with a key, both
// given directly as command-line arguments, and prints the plaintext.
//
// Usage:
//
//	golock-decrypt <hex-key> <base64-ciphertext> [aad]
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
		fmt.Fprintln(os.Stderr, "usage: golock-decrypt <hex-key> <base64-ciphertext> [aad]")
		os.Exit(2)
	}
	hexKey, b64Ciphertext := os.Args[1], os.Args[2]

	key, err := golock.DecodeKey(hexKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: decoding key:", err)
		os.Exit(1)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: decoding ciphertext:", err)
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

	plaintext, err := box.Decrypt(ciphertext)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: decrypt failed:", err)
		os.Exit(1)
	}

	fmt.Println(string(plaintext))
}
