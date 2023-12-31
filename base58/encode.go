// Package base58 handles encoding/decoding of base58.
// This package provides functions that work constant-time, as well as their variable-time counterparts.
package base58

import (
	"crypto/subtle"
	"math/big"
)

// VartimeEncode encodes a byte slice into a base58 string with length resultLength.
//
// This function does not have a constant-time guarantee.
func VartimeEncode(a []byte, resultLength int) string {
	tmp := big.NewInt(0)
	radix := big.NewInt(58)
	tmp.SetBytes(a)
	result := make([]byte, resultLength)
	alphabet := []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	for i := 0; i < resultLength; i++ {
		var remainder big.Int
		tmp.DivMod(tmp, radix, &remainder)
		index := remainder.Int64()
		result[resultLength-1-i] = alphabet[index]
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
	deletedQuarterBits := 0
	for i := 0; i < resultLength; i++ {
		remainder := div58(tmp[min(len(tmp), deletedQuarterBits/128):])
		char := '1' + remainder                                                                              // [0,9): '1'..'9'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(9, remainder), 'A'+remainder-9, char)   // [9,17): 'A'..'H'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(17, remainder), 'J'+remainder-17, char) // [17,22): 'J'..'N'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(22, remainder), 'P'+remainder-22, char) // [22,33): 'P'..'Z'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(33, remainder), 'a'+remainder-33, char) // [33,44): 'a'..'k'
		char = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq(44, remainder), 'm'+remainder-44, char) // [44,58): 'm'..'z'
		result[resultLength-1-i] = byte(char)
		deletedQuarterBits += 23
	}
	return string(result)
}

func div58(a []uint32) int {
	var carry int64
	for i := 0; i < len(a); i++ {
		tmp := carry<<32 | int64(a[i])
		q := tmp / 58
		r := tmp % 58
		a[i] = uint32(q)
		carry = r
	}
	return int(carry)
}
