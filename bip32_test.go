package bip32

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVector(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	extPub := "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
	extPrv := "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
	master := NewMasterKey(seed)
	serPrv := vartimeBase58Encode(master.Serialize())
	serPub := vartimeBase58Encode(master.GetPublicKey().Serialize())
	assert.Equal(t, extPub, serPub)
	assert.Equal(t, extPrv, serPrv)
	childH0, _ := master.NewChildKey(FirstHardenedChildIndex + 0)
	extPrv0 := "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
	serPrv0 := vartimeBase58Encode(childH0.Serialize())
	assert.Equal(t, extPrv0, serPrv0)
}
