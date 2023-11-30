package bip32

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"math/big"

	"golang.org/x/crypto/ripemd160"
)

func uint32ToBytes(a uint32) [4]byte {
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], a)
	return result
}

func hmacThing(chainCode [32]byte, keyElement [33]byte, childIdx uint32) [64]byte {
	hash := hmac.New(sha512.New, chainCode[:])
	_, _ = hash.Write(keyElement[:])
	value := uint32ToBytes(childIdx)
	_, _ = hash.Write(value[:])
	return [64]byte(hash.Sum(nil))
}

func hash160(a []byte) []byte {
	hash := ripemd160.New()
	intermediate := sha256.Sum256(a)
	hash.Write(intermediate[:])
	return hash.Sum(nil)
}

func checksum(a []byte) [4]byte {
	intermediate := sha256.Sum256(a)
	hash := sha256.Sum256(intermediate[:])
	return [4]byte(hash[:4])
}

func vartimeBase58Encode(a [82]byte) string {
	tmp := big.NewInt(0)
	radix := big.NewInt(58)
	tmp.SetBytes(a[:])
	result := make([]byte, 111)
	alphabet := []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	for i := 0; i < 111; i++ {
		var remainder big.Int
		tmp.DivMod(tmp, radix, &remainder)
		index := remainder.Int64()
		result[110-i] = alphabet[index]
	}
	return string(result)
}

func base58Encode(a [82]byte) string {
	result := make([]byte, 111)
	for i := 0; i < 111; i++ {
		remainder := div58(&a)
		char := '1' + remainder                                                                              // [0,9): '1'..'9'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(9, remainder), 'A'+remainder-9, char)   // [9,17): 'A'..'H'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(17, remainder), 'J'+remainder-17, char) // [17,22): 'J'..'N'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(22, remainder), 'P'+remainder-22, char) // [22,33): 'P'..'Z'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(33, remainder), 'a'+remainder-33, char) // [33,44): 'a'..'k'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(44, remainder), 'm'+remainder-44, char) // [44,58): 'm'..'z'
		result[110-i] = byte(char)
	}
	return string(result)
}

func div58(a *[82]byte) int {
	var carry int
	for i := 0; i < len(a); i++ {
		tmp := carry<<8 | int(a[i])
		q := tmp / 58
		r := tmp % 58
		a[i] = byte(q)
		carry = r
	}
	return carry
}
