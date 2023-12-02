package bip32

import (
	"encoding/hex"

	"github.com/koba-e964/bip32-typesafe/base58"
)

const FirstHardenedChildIndex uint32 = 0x80000000

const KeyLengthInBytes = 82

var (
	publicKeyVersion, _         = hex.DecodeString("0488B21E")
	privateKeyVersion, _        = hex.DecodeString("0488ADE4")
	testnetPublicKeyVersion, _  = hex.DecodeString("043587CF")
	testnetPrivateKeyVersion, _ = hex.DecodeString("04358394")
)

func base58EncodeKeyBytes(a [82]byte) string {
	return base58.Encode(a[:], 111)
}
