package bip32

import "encoding/binary"

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
