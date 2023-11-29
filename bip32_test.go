package bip32

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

type child struct {
	index uint32
	key   keyPair
}

type keyPair struct {
	extPub   string // expected seralized public key
	extPrv   string // expected seralized private key
	children []child
}

type testVector struct {
	seed string // hex string
	key  keyPair
}

var tests = []testVector{
	{
		seed: "000102030405060708090a0b0c0d0e0f",
		key: keyPair{
			extPub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
			extPrv: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
			children: []child{
				{
					index: FirstHardenedChildIndex + 0,
					key: keyPair{
						extPub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
						extPrv: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
						children: []child{
							{
								index: 1,
								key: keyPair{
									extPub: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
									extPrv: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
									children: []child{
										{
											index: FirstHardenedChildIndex + 2,
											key: keyPair{
												extPub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
												extPrv: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
												children: []child{
													{
														index: 2,
														key: keyPair{
															extPub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
															extPrv: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
															children: []child{
																{
																	index: 1000000000,
																	key: keyPair{
																		extPub: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
																		extPrv: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	},
}

func TestVector(t *testing.T) {
	for _, vector := range tests {

		seed, _ := hex.DecodeString(vector.seed)
		master := NewMasterKey(seed)
		serPrv := vartimeBase58Encode(master.Serialize())
		serPub := vartimeBase58Encode(master.GetPublicKey().Serialize())
		assert.Equal(t, vector.key.extPub, serPub)
		assert.Equal(t, vector.key.extPrv, serPrv)
		for _, child := range vector.key.children {
			testChild(t, master, master.GetPublicKey(), child)
		}
	}
}

func testChild(t *testing.T, prv *PrivateKey, pub *PublicKey, child child) {
	childPrv, err := prv.NewChildKey(child.index)
	assert.Nil(t, err)
	childPub := childPrv.GetPublicKey()
	serPrv0 := vartimeBase58Encode(childPrv.Serialize())
	serPub0 := vartimeBase58Encode(childPub.Serialize())
	assert.Equal(t, child.key.extPrv, serPrv0)
	assert.Equal(t, child.key.extPub, serPub0)
	if child.index < FirstHardenedChildIndex {
		childPubFromPub, err := pub.NewChildKey(child.index)
		assert.Nil(t, err)
		assert.Equal(t, childPub, childPubFromPub)
	}
	for _, grandchild := range child.key.children {
		testChild(t, childPrv, childPub, grandchild)
	}
}
