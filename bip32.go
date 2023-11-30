package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const FirstHardenedChildIndex uint32 = 0x80000000

const KeyLengthInBytes = 82

var (
	publicKeyVersion, _         = hex.DecodeString("0488B21E")
	privateKeyVersion, _        = hex.DecodeString("0488ADE4")
	testnetPublicKeyVersion, _  = hex.DecodeString("043587CF")
	testnetPrivateKeyVersion, _ = hex.DecodeString("04358394")
)

var (
	ErrorHardenedPublicChildKey = errors.New("can't create a hardened child key from a public key")
	ErrorTooDeepKey             = errors.New("depth can't be >= 256")
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

type PrivateKey struct {
	version           [4]byte // privateKeyVersion or testnetPrivateKeyVersion
	depth             byte
	parentFingerprint [4]byte
	childNumber       [4]byte
	chainCode         [32]byte
	privateKey        [32]byte
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
		publicKey:         compress(gePoint(p.privateKey)),
	}
	return &publicKey
}

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

func (p *PrivateKey) NewChildKey(childIdx uint32) (*PrivateKey, error) {
	if p.depth >= 255 {
		return nil, ErrorTooDeepKey
	}
	pubPart := compress(gePoint(p.privateKey))
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
		privateKey:        scAdd(ll, p.privateKey),
	}
	return &child, nil
}

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
