package golock

// Option configures a Box at construction time.
type Option func(*Box) error

// WithKey adds an additional key to a Box for key-rotation support.
//
// Keys added this way are only ever used for Decrypt: Box tries the
// primary key passed to New first, then each additional key in the order
// they were added, mirroring Ruby Lockbox's key rotation behavior where
// `encrypt` always uses the first/primary key but `decrypt` accepts any
// of several keys. key must be the raw 32-byte key (see DecodeKey for
// decoding a hex-encoded key).
func WithKey(key []byte) Option {
	return func(l *Box) error {
		enc, err := newEncryptor(key)
		if err != nil {
			return err
		}
		l.encryptors = append(l.encryptors, enc)
		return nil
	}
}

// WithHexKey is like WithKey but accepts a hex-encoded key string, as
// produced by GenerateKey.
func WithHexKey(hexKey string) Option {
	return func(l *Box) error {
		key, err := DecodeKey(hexKey)
		if err != nil {
			return err
		}
		enc, err := newEncryptor(key)
		if err != nil {
			return err
		}
		l.encryptors = append(l.encryptors, enc)
		return nil
	}
}

// WithAAD sets a default associated-data value used by Encrypt/Decrypt
// when no explicit AAD is given via EncryptWithAAD/DecryptWithAAD,
// mirroring Ruby Lockbox's Box.new(associated_data:) option (gem v1.2.0+;
// present in the v1.4.1 version this package targets).
func WithAAD(aad []byte) Option {
	return func(l *Box) error {
		l.defaultAAD = aad
		return nil
	}
}
