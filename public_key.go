package bip32

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/koba-e964/bip32-typesafe/base58"
)

type PublicKey struct {
	version           [4]byte // publicKeyVersion or testnetPublicKeyVersion
	depth             byte
	parentFingerprint [4]byte
	childNumber       [4]byte
	chainCode         [32]byte
	publicKey         [33]byte
}

func (p *PublicKey) Depth() byte {
	return p.depth
}

func (p *PublicKey) ParentFingerprint() [4]byte {
	return p.parentFingerprint
}

func (p *PublicKey) ChildNumber() uint32 {
	return binary.BigEndian.Uint32(p.childNumber[:])
}

func (p *PublicKey) ChainCode() [32]byte {
	return p.chainCode
}

func (p *PublicKey) PublicKey() [33]byte {
	return p.publicKey
}

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

// B58Serialize returns the base58 representation of this `PublicKey`.
func (p *PublicKey) B58Serialize() string {
	return base58EncodeKeyBytes(p.Serialize())
}

// B58DeserializePublicKey decodes base58-encoded strings and
// returns a `PublicKey`.
func B58DeserializePublicKey(encoded string) (*PublicKey, error) {
	if len(encoded) != 111 {
		return nil, ErrorInvalidKeyLength
	}
	var data [82]byte
	base58.Decode(encoded, data[:])
	return DeserializePublicKey(data)
}

// DeserializePublicKey reads a []byte and
// returns a `PublicKey`.
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

	return &p, nil
}

func (p *PublicKey) NewChildKey(childIdx uint32) (*PublicKey, error) {
	if childIdx >= FirstHardenedChildIndex {
		return nil, ErrorHardenedPublicChildKey
	}
	if p.depth >= 255 {
		return nil, ErrorTooDeepKey
	}
	uncompressed, err := uncompress(p.publicKey)
	if err != nil {
		return nil, err
	}
	l := hmacThing(p.chainCode, p.publicKey, childIdx)
	ll := [32]byte(l[:32])
	lr := [32]byte(l[32:])
	derivedPubKey := geAdd(uncompressed, gePoint(ll))
	child := PublicKey{
		version:           p.version,
		depth:             p.depth + 1,
		parentFingerprint: [4]byte(hash160(p.publicKey[:])),
		childNumber:       uint32ToBytes(childIdx),
		chainCode:         lr,
		publicKey:         compress(derivedPubKey),
	}
	return &child, nil
}
