// Package bip32 provides BIP 32 related functions.
//
// Spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
)

var (
	ErrorHardenedPublicChildKey               = errors.New("can't create a hardened child key from a public key")
	ErrorTooDeepKey                           = errors.New("depth can't be >= 256")
	ErrorInvalidKeyLength                     = errors.New("invalid key length")
	ErrorInvalidVersion                       = errors.New("version is invalid")
	ErrorInvalidPublicKey                     = errors.New("public key is invalid")
	ErrorInvalidPrivateKey                    = errors.New("private key is invalid")
	ErrorChecksumMismatch                     = errors.New("checksum mismatch")
	ErrorZeroDepthAndNonZeroParentFingerprint = errors.New("zero depth with non-zero parent fingerprint")
	ErrorZeroDepthAndNonZeroIndex             = errors.New("zero depth with non-zero index")
	ErrorPrivateKeyNotInRange                 = errors.New("private key not in range (1 <= p <= n-1)")
)

// NewMasterKey generates a new master private key with the given seed.
//
// Example:
//
//	// the length of a seed should be between 128 and 512 bits;
//	// this length (32 bits) is too short and for illustration purpose only
//	seed, err := hex.DecodeString("01020304")
//	master := NewMasterKey(seed)
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

// MasterPublicKeyFromRaw returns a master public key for mainnet with the given public key and the chain code.
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
