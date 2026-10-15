package golock

import "context"

// KeyProvider wraps/unwraps a data encryption key using an external key
// management service (KMS). This mirrors Ruby Lockbox's pluggable KMS
// support (AWS KMS, Google Cloud KMS, Azure Key Vault, HashiCorp Vault),
// letting a master key be stored encrypted-at-rest by a KMS instead of
// (or in addition to) being supplied directly to the application.
//
// Implementations are expected to live in subpackages (e.g. a future
// golock/kms/awskms package) so that the core module does not pull in
// cloud SDK dependencies. This file only defines the interface; no
// concrete KMS implementations are provided yet.
type KeyProvider interface {
	// EncryptKey wraps (encrypts) a raw key using the KMS, returning the
	// wrapped key material that can be safely stored at rest.
	EncryptKey(ctx context.Context, key []byte) ([]byte, error)

	// DecryptKey unwraps (decrypts) previously-wrapped key material,
	// returning the raw key.
	DecryptKey(ctx context.Context, wrapped []byte) ([]byte, error)
}

// Known/planned KMS provider identifiers. These are placeholders for
// future KeyProvider implementations (e.g. golock/kms/awskms,
// golock/kms/gcpkms, golock/kms/vaultkms) and are not yet implemented.
const (
	// ProviderAWS identifies an AWS KMS-backed KeyProvider (not yet implemented).
	ProviderAWS = "aws"
	// ProviderGoogleCloud identifies a Google Cloud KMS-backed KeyProvider (not yet implemented).
	ProviderGoogleCloud = "gcp"
	// ProviderAzure identifies an Azure Key Vault-backed KeyProvider (not yet implemented).
	ProviderAzure = "azure"
	// ProviderVault identifies a HashiCorp Vault-backed KeyProvider (not yet implemented).
	ProviderVault = "vault"
)
