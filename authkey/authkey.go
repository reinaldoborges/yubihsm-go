package authkey

import (
	"crypto/sha256"

	"crypto/pbkdf2"
)

type (
	// AuthKey is a key to authenticate with the HSM
	AuthKey []byte
)

const (
	authKeyLength     = 32
	authKeyIterations = 10000
	yubicoSeed        = "Yubico"
)

// NewFromPassword derives an AuthKey using pkdf2 as specified in the HSM documentation
func NewFromPassword(password string) AuthKey {
	key, _ := pbkdf2.Key(sha256.New, password, []byte(yubicoSeed), authKeyIterations, authKeyLength)
	return AuthKey(key)
}

// GetEncKey returns the EncryptionKey part of the AuthKey
func (k AuthKey) GetEncKey() []byte {
	return k[:authKeyLength/2]
}

// GetMacKey returns the MACKey part of the AuthKey
func (k AuthKey) GetMacKey() []byte {
	return k[authKeyLength/2:]
}
