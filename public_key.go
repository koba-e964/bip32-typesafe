package bip32

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/koba-e964/base58-go"
	"github.com/koba-e964/bip32-typesafe/secp256k1"
)

// PublicKey is a public key.
type PublicKey struct {
	version           [4]byte // publicKeyVersion or testnetPublicKeyVersion
	depth             byte
	parentFingerprint [4]byte
	childNumber       [4]byte
	chainCode         [32]byte
	publicKey         secp256k1.Compressed
}

// Depth returns the depth of this PublicKey. If the depth is 0, this key is a master key.
func (p *PublicKey) Depth() byte {
	return p.depth
}

// ParentFingerprint returns the fingerprint of this PublicKey's parent key. If this key is a master key, the fingerprint is filled with zero.
func (p *PublicKey) ParentFingerprint() [4]byte {
	return p.parentFingerprint
}

// ChildNumber returns the child index of this PublicKey. If this PublicKey is a master key, this function returns 0.
func (p *PublicKey) ChildNumber() uint32 {
	return binary.BigEndian.Uint32(p.childNumber[:])
}

// ChainCode returns the chain code of this PublicKey. This value is used in derivation of child public keys.
func (p *PublicKey) ChainCode() [32]byte {
	return p.chainCode
}

// PublicKey returns the public key of secp256k1 (a compressed point) in this PublicKey.
func (p *PublicKey) PublicKey() secp256k1.Compressed {
	return p.publicKey
}

// Serialize returns the []byte representation of this PublicKey.
func (p *PublicKey) Serialize() [KeyLengthInBytes]byte {
	var result [KeyLengthInBytes]byte

	copy(result[:4], p.version[:])

	result[4] = p.depth

	copy(result[5:9], p.parentFingerprint[:])

	copy(result[9:13], p.childNumber[:])

	copy(result[13:45], p.chainCode[:])

	copy(result[45:78], p.publicKey[:])

	chksum := checksum(result[:78])
	copy(result[78:], chksum[:])

	return result
}

// B58Serialize returns the base58 representation of this PublicKey.
func (p *PublicKey) B58Serialize() string {
	return base58EncodeKeyBytes(p.Serialize())
}

// B58DeserializePublicKey decodes a base58-encoded string and
// returns a PublicKey.
func B58DeserializePublicKey(encoded string) (*PublicKey, error) {
	if len(encoded) != 111 {
		return nil, ErrorInvalidKeyLength
	}
	var data [82]byte
	base58.Decode(encoded, data[:])
	return DeserializePublicKey(data)
}

// DeserializePublicKey reads a []byte and
// returns a PublicKey.
func DeserializePublicKey(data [KeyLengthInBytes]byte) (*PublicKey, error) {
	p := PublicKey{}

	chksum := checksum(data[:78])
	if subtle.ConstantTimeCompare(data[78:], chksum[:]) != 1 {
		return nil, ErrorChecksumMismatch
	}

	if (subtle.ConstantTimeCompare(data[:4], publicKeyVersion) | subtle.ConstantTimeCompare(data[:4], testnetPublicKeyVersion)) != 1 {
		return nil, ErrorInvalidVersion
	}
	p.version = [4]byte(data[:4])

	p.depth = data[4]

	copy(p.parentFingerprint[:], data[5:9])

	if (subtle.ConstantTimeByteEq(p.depth, 0) & (subtle.ConstantTimeCompare(p.parentFingerprint[:], make([]byte, 4)) ^ 1)) == 1 {
		return nil, ErrorZeroDepthAndNonZeroParentFingerprint
	}

	copy(p.childNumber[:], data[9:13])

	if (subtle.ConstantTimeByteEq(p.depth, 0) & (subtle.ConstantTimeCompare(p.childNumber[:], make([]byte, 4)) ^ 1)) == 1 {
		return nil, ErrorZeroDepthAndNonZeroIndex
	}

	copy(p.chainCode[:], data[13:45])

	if (data[45] & 2) != 2 {
		return nil, ErrorInvalidPublicKey
	}
	copy(p.publicKey[:], data[45:78])

	// checks if p.publicKey is valid
	if _, err := p.publicKey.Uncompress(); err != nil {
		return nil, ErrorInvalidPublicKey
	}

	return &p, nil
}

// NewChildKey derives a new child key from this PublicKey. The following errors may be returned:
//   - ErrorHardenedPublicChildKey: if childIdx >= FirstHardenedChildIndex = 0x80000000
//   - ErrorTooDeepKey: if this PublicKey has depth 255
//   - ErrorInvalidPublicKey: if the derived public key satisfies parse_{256}(I_L) >= n (with probability < 2^{-127})
func (p *PublicKey) NewChildKey(childIdx uint32) (*PublicKey, error) {
	if childIdx >= FirstHardenedChildIndex {
		return nil, ErrorHardenedPublicChildKey
	}
	if p.depth == 255 {
		return nil, ErrorTooDeepKey
	}
	uncompressed, err := p.publicKey.Uncompress()
	if err != nil {
		return nil, err
	}
	l := hmacThing(p.chainCode, p.publicKey, childIdx)
	ll := [32]byte(l[:32])
	lr := [32]byte(l[32:])
	var derivedPubKey secp256k1.Point
	var llPoint secp256k1.Point
	llPoint.GEPoint(ll)
	derivedPubKey.GEAdd(uncompressed, &llPoint)
	child := PublicKey{
		version:           p.version,
		depth:             p.depth + 1,
		parentFingerprint: [4]byte(hash160(p.publicKey[:])),
		childNumber:       uint32ToBytes(childIdx),
		chainCode:         lr,
		publicKey:         derivedPubKey.Compress(),
	}
	cmp := secp256k1.SCIsValid(ll)
	if cmp != 1 {
		return nil, ErrorInvalidPrivateKey
	}
	return &child, nil
}
