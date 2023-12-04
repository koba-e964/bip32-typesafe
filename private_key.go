package bip32

import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/koba-e964/bip32-typesafe/base58"
	"github.com/koba-e964/bip32-typesafe/secp256k1"
)

type PrivateKey struct {
	version           [4]byte // privateKeyVersion or testnetPrivateKeyVersion
	depth             byte
	parentFingerprint [4]byte
	childNumber       [4]byte
	chainCode         [32]byte
	privateKey        secp256k1.Scalar
}

func (p *PrivateKey) Depth() byte {
	return p.depth
}

func (p *PrivateKey) ParentFingerprint() [4]byte {
	return p.parentFingerprint
}

func (p *PrivateKey) ChildNumber() uint32 {
	return binary.BigEndian.Uint32(p.childNumber[:])
}

func (p *PrivateKey) ChainCode() [32]byte {
	return p.chainCode
}

func (p *PrivateKey) PrivateKey() [32]byte {
	return p.privateKey
}

func (p *PrivateKey) GetPublicKey() *PublicKey {
	version := publicKeyVersion
	if p.version == [4]byte(testnetPrivateKeyVersion) {
		version = testnetPublicKeyVersion
	}
	publicKey := PublicKey{
		version:           [4]byte(version),
		depth:             p.depth,
		parentFingerprint: p.parentFingerprint,
		childNumber:       p.childNumber,
		chainCode:         p.chainCode,
		publicKey:         secp256k1.GEPoint(p.privateKey).Compress(),
	}
	return &publicKey
}

// B58Serialize returns the []byte representation of this `PrivateKey`.
func (p *PrivateKey) Serialize() [KeyLengthInBytes]byte {
	var result [KeyLengthInBytes]byte

	copy(result[:4], p.version[:])

	result[4] = p.depth

	copy(result[5:9], p.parentFingerprint[:])

	copy(result[9:13], p.childNumber[:])

	copy(result[13:45], p.chainCode[:])

	// result[45] = 0 is implicitly achieved

	copy(result[46:78], p.privateKey[:])

	chksum := checksum(result[:78])
	copy(result[78:], chksum[:])

	return result
}

// B58Serialize returns the base58 representation of this `PrivateKey`.
func (p *PrivateKey) B58Serialize() string {
	return base58EncodeKeyBytes(p.Serialize())
}

// B58DeserializePublicKey decodes base58-encoded strings and
// returns a `PublicKey`.
func B58DeserializePrivateKey(encoded string) (*PrivateKey, error) {
	if len(encoded) != 111 {
		return nil, ErrorInvalidKeyLength
	}
	var data [82]byte
	base58.Decode(encoded, data[:])
	return DeserializePrivateKey(data)
}

// DeserializePublicKey reads a []byte and
// returns a `PublicKey`.
func DeserializePrivateKey(data [KeyLengthInBytes]byte) (*PrivateKey, error) {
	p := PrivateKey{}

	chksum := checksum(data[:78])
	if subtle.ConstantTimeCompare(data[78:], chksum[:]) != 1 {
		return nil, ErrorChecksumMismatch
	}

	if (subtle.ConstantTimeCompare(data[:4], privateKeyVersion) | subtle.ConstantTimeCompare(data[:4], testnetPrivateKeyVersion)) != 1 {
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

	if data[45] != 0 {
		return nil, ErrorInvalidPrivateKey
	}
	copy(p.privateKey[:], data[46:78])

	// 0 < privateKey < secp256k1.Order
	inRange := subtle.ConstantTimeEq(int32(secp256k1.CompareBytes([32]byte{}, p.privateKey)), -1) &
		subtle.ConstantTimeEq(int32(secp256k1.CompareBytes(p.privateKey, secp256k1.Order)), -1)
	if inRange != 1 {
		return nil, ErrorPrivateKeyNotInRange
	}

	return &p, nil
}

func (p *PrivateKey) NewChildKey(childIdx uint32) (*PrivateKey, error) {
	if p.depth >= 255 {
		return nil, ErrorTooDeepKey
	}
	pubPart := secp256k1.GEPoint(p.privateKey).Compress()
	keyData := [33]byte(append([]byte{0x00}, p.privateKey[:]...))
	if childIdx < FirstHardenedChildIndex {
		keyData = pubPart
	}
	l := hmacThing(p.chainCode, keyData, childIdx)
	ll := [32]byte(l[:32])
	lr := [32]byte(l[32:])
	child := PrivateKey{
		version:           p.version,
		depth:             p.depth + 1,
		parentFingerprint: [4]byte(hash160(pubPart[:])[:4]),
		childNumber:       uint32ToBytes(childIdx),
		chainCode:         lr,
		privateKey:        secp256k1.SCAdd(ll, p.privateKey),
	}
	return &child, nil
}
