package base58

import (
	"crypto/subtle"
	"math/big"
	"unsafe"
)

// Using the idea described in https://github.com/btcsuite/btcd/blob/13152b35e191385a874294a9dbc902e48b1d71b0/btcutil/base58/base58.go#L34-L49
var (
	radix10  = new(big.Int).Exp(big.NewInt(58), big.NewInt(10), nil) // 58^10 < 2^64
	alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
)

// VartimeEncode encodes a byte slice into a base58 string with length resultLength.
//
// This function does not have a constant-time guarantee.
func VartimeEncode(a []byte, resultLength int) string {
	tmp := big.NewInt(0)
	tmp.SetBytes(a)
	result := make([]byte, resultLength)
	for i := 0; i < resultLength; i += 10 {
		var remainder big.Int
		tmp.DivMod(tmp, radix10, &remainder)
		remainder64 := remainder.Uint64()
		for j := 0; j < 10; j++ {
			if i+j < resultLength {
				rem58 := remainder64 % 58
				remainder64 /= 58
				result[resultLength-1-i-j] = alphabet[int(rem58)]
			}
		}
	}
	return string(result)
}

// Encode encodes a byte slice into a base58 string with length resultLength.
//
// This function runs in constant time.
func Encode(a []byte, resultLength int) string {
	aLen := len(a)
	tmp := make([]uint32, (aLen+3)/4)
	for i := 0; i < aLen; i++ {
		tmp[len(tmp)-1-i/4] |= uint32(a[aLen-1-i]) << (8 * (i % 4))
	}
	result := make([]byte, resultLength)
	// log(58)/log(2) > 5.857 > 23/4, so every 4 letters we can delete 23 bits
	deletedBits := 0
	for i := 0; i < resultLength; i += 4 {
		rems := div58(tmp[min(len(tmp), deletedBits/32):])
		conv := func(remainder int) byte {
			char := '1' + remainder                                                                              // [0,9): '1'..'9'
			char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(9, remainder), 'A'+remainder-9, char)   // [9,17): 'A'..'H'
			char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(17, remainder), 'J'+remainder-17, char) // [17,22): 'J'..'N'
			char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(22, remainder), 'P'+remainder-22, char) // [22,33): 'P'..'Z'
			char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(33, remainder), 'a'+remainder-33, char) // [33,44): 'a'..'k'
			char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(44, remainder), 'm'+remainder-44, char) // [44,58): 'm'..'z'
			return byte(char)
		}
		result[resultLength-1-i] = conv(rems[0])
		for j := 1; j < 4; j++ {
			if i+j < resultLength {
				result[resultLength-1-i-j] = conv(rems[j])
			}
		}
		deletedBits += 23
	}
	return unsafe.String(unsafe.SliceData(result), len(result))
}

func div58(a []uint32) [4]int {
	// Using the idea described in https://github.com/btcsuite/btcd/blob/13152b35e191385a874294a9dbc902e48b1d71b0/btcutil/base58/base58.go#L34-L49
	const d = 58 * 58 * 58 * 58
	var carry uint64
	for i := 0; i < len(a); i++ {
		tmp := carry<<32 | uint64(a[i])
		q := tmp / d
		a[i] = uint32(q)
		carry = tmp - q*d
	}
	var res [4]int
	for i := 0; i < 4; i++ {
		res[i] = int(carry % 58)
		carry /= 58
	}
	return res
}
