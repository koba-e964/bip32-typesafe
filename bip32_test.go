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

// Test Vectors from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
var tests = []testVector{
	// Test vector 1
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
	// Test vector 3
	{
		seed: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
		key: keyPair{
			extPub: "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
			extPrv: "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
			children: []child{
				{
					index: FirstHardenedChildIndex + 0,
					key: keyPair{
						extPub: "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
						extPrv: "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
					},
				},
			},
		},
	},
	// Test vector 4
	{
		seed: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
		key: keyPair{
			extPub: "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
			extPrv: "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
			children: []child{
				{
					index: FirstHardenedChildIndex + 0,
					key: keyPair{
						extPub: "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
						extPrv: "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
						children: []child{
							{
								index: FirstHardenedChildIndex + 1,
								key: keyPair{
									extPub: "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
									extPrv: "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
								},
							},
						},
					},
				},
			},
		},
	},
}

func TestVectors(t *testing.T) {
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
