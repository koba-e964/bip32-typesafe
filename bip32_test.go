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
		serPrv := master.B58Serialize()
		serPub := master.GetPublicKey().B58Serialize()
		assert.Equal(t, vector.key.extPub, serPub)
		assert.Equal(t, vector.key.extPrv, serPrv)
		deserPrv0, err := B58DeserializePrivateKey(vector.key.extPrv)
		assert.Nil(t, err)
		deserPub0, err := B58DeserializePublicKey(vector.key.extPub)
		assert.Nil(t, err)
		assert.Equal(t, master.GetPublicKey(), deserPub0)
		assert.Equal(t, master, deserPrv0)
		for _, child := range vector.key.children {
			testChild(t, master, master.GetPublicKey(), child)
		}
	}
}

func testChild(t *testing.T, prv *PrivateKey, pub *PublicKey, child child) {
	childPrv, err := prv.NewChildKey(child.index)
	assert.Nil(t, err)
	childPub := childPrv.GetPublicKey()
	serPrv0 := childPrv.B58Serialize()
	serPub0 := childPub.B58Serialize()
	assert.Equal(t, child.key.extPrv, serPrv0)
	assert.Equal(t, child.key.extPub, serPub0)
	deserPrv0, err := B58DeserializePrivateKey(child.key.extPrv)
	assert.Nil(t, err)
	deserPub0, err := B58DeserializePublicKey(child.key.extPub)
	assert.Nil(t, err)
	assert.Equal(t, childPrv, deserPrv0)
	assert.Equal(t, childPub, deserPub0)
	if child.index < FirstHardenedChildIndex {
		childPubFromPub, err := pub.NewChildKey(child.index)
		assert.Nil(t, err)
		assert.Equal(t, childPub, childPubFromPub)
	}
	for _, grandchild := range child.key.children {
		testChild(t, childPrv, childPub, grandchild)
	}
}

var pubkeyFailureVectors = []struct {
	encoded     string
	expectedErr error
}{
	{
		encoded:     "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
		expectedErr: ErrorInvalidPublicKey,
	},
	{
		encoded:     "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
		expectedErr: ErrorInvalidPublicKey,
	},
	{
		encoded:     "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
		expectedErr: ErrorInvalidPublicKey,
	},
	{
		encoded:     "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
		expectedErr: ErrorZeroDepthAndNonZeroParentFingerprint,
	},
	{
		encoded:     "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
		expectedErr: ErrorZeroDepthAndNonZeroIndex,
	},
	{
		encoded:     "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
		expectedErr: ErrorInvalidVersion,
	},
	{
		encoded:     "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
		expectedErr: ErrorInvalidPublicKey,
	},
}

func TestPubkeyFailureVectors(t *testing.T) {
	for _, vector := range pubkeyFailureVectors {
		pub, err := B58DeserializePublicKey(vector.encoded)
		assert.Nil(t, pub, vector.encoded, vector.expectedErr)
		assert.Equal(t, vector.expectedErr, err, vector.encoded, vector.expectedErr)
	}
}

var privkeyFailureVectors = []struct {
	encoded     string
	expectedErr error
}{
	{
		encoded:     "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
		expectedErr: ErrorInvalidPrivateKey,
	},
	{
		encoded:     "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
		expectedErr: ErrorInvalidPrivateKey,
	},
	{
		encoded:     "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
		expectedErr: ErrorInvalidPrivateKey,
	},
	{
		encoded:     "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
		expectedErr: ErrorZeroDepthAndNonZeroParentFingerprint,
	},
	{
		encoded:     "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
		expectedErr: ErrorZeroDepthAndNonZeroIndex,
	},
	{
		encoded:     "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
		expectedErr: ErrorInvalidVersion,
	},
	{
		encoded:     "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
		expectedErr: ErrorPrivateKeyNotInRange,
	},
	{
		encoded:     "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
		expectedErr: ErrorPrivateKeyNotInRange,
	},
	{
		encoded:     "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
		expectedErr: ErrorChecksumMismatch,
	},
}

func TestPrivkeyFailureVectors(t *testing.T) {
	for _, vector := range privkeyFailureVectors {
		priv, err := B58DeserializePrivateKey(vector.encoded)
		assert.Nil(t, priv, vector.encoded, vector.expectedErr)
		assert.Equal(t, vector.expectedErr, err, vector.encoded, vector.expectedErr)
	}
}
