package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
)

var (
	ErrorHardenedPublicChildKey = errors.New("can't create a hardened child key from a public key")
	ErrorTooDeepKey             = errors.New("depth can't be >= 256")
	ErrorInvalidKeyLength       = errors.New("invalid key length")
	ErrorInvalidVersion         = errors.New("version is invalid")
	ErrorInvalidPublicKey       = errors.New("public key is invalid")
	ErrorInvalidPrivateKey      = errors.New("private key is invalid")
	ErrorChecksumMismatch       = errors.New("checksum mismatch")
)

func NewMasterKey(seed []byte) *PrivateKey {
	hmac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, _ = hmac.Write(seed)
	l := hmac.Sum(nil)
	ll := [32]byte(l[:32])
	lr := [32]byte(l[32:])
	master := PrivateKey{
		version:           [4]byte(privateKeyVersion),
		depth:             0,
		parentFingerprint: [4]byte{},
		childNumber:       [4]byte{},
		chainCode:         lr,
		privateKey:        ll,
	}
	return &master
}

// MasterPublicKeyFromRaw returns a master public key for mainnet with the given `publicKey` and `chainCode`.
func MasterPublicKeyFromRaw(publicKey [33]byte, chainCode [32]byte) *PublicKey {
	master := PublicKey{
		version:           [4]byte(publicKeyVersion),
		depth:             0,
		parentFingerprint: [4]byte{},
		childNumber:       [4]byte{},
		chainCode:         chainCode,
		publicKey:         publicKey,
	}
	return &master
}
