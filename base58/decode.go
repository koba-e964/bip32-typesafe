package base58

import (
	"crypto/subtle"
	"math/big"
)

// VartimeDecode writes into output.
//
// If the resulting integer doesn't fit in output,
// the higher part will be truncated.
//
// This function does not have a constant-time guarantee.
func VartimeDecode(encoded string, output []byte) {
	tmp := big.NewInt(0)
	radix := big.NewInt(58)
	targetLen := len(output)
	for i := 0; i < len(encoded); i++ {
		char := encoded[i]
		index := char - '1'
		if char >= 'A' {
			index = char - 'A' + 9
		}
		if char >= 'J' {
			index = char - 'J' + 17
		}
		if char >= 'P' {
			index = char - 'P' + 22
		}
		if char >= 'a' {
			index = char - 'a' + 33
		}
		if char >= 'm' {
			index = char - 'm' + 44
		}
		tmp.Mul(tmp, radix).Add(tmp, big.NewInt(int64(index)))
	}
	if tmp.BitLen() > 8*targetLen {
		mask := big.NewInt(1)
		mask.Lsh(mask, 8*uint(targetLen))
		mask.Sub(mask, big.NewInt(1))
		tmp.And(tmp, mask)
	}
	tmp.FillBytes(output)
}

// Decode writes into output.
//
// If the resulting integer doesn't fit in output,
// the higher part will be truncated.
//
// This function runs in constant time.
func Decode(encoded string, output []byte) {
	targetLen := len(output)
	tmp := make([]uint32, (targetLen+3)/4)
	for i := 0; i < len(encoded); i++ {
		char := int(encoded[i])
		index := char - '1'                                                                           // [0,9): '1'..'9'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('A', char), char-'A'+9, index)  // [9,17): 'A'..'H'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('J', char), char-'J'+17, index) // [17,22): 'J'..'N'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('P', char), char-'P'+22, index) // [22,33): 'P'..'Z'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('a', char), char-'a'+33, index) // [33,44): 'a'..'k'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('m', char), char-'m'+44, index) // [44,58): 'm'..'z'
		mul58Add(tmp, index)
	}
	for i := 0; i < targetLen; i++ {
		output[targetLen-1-i] = byte(tmp[len(tmp)-1-i/4] >> (8 * (i % 4)))
	}
}

func mul58Add(a []uint32, addendum int) {
	carry := int64(addendum)
	for i := len(a) - 1; i >= 0; i-- {
		tmp := int64(a[i])*58 + carry
		thisCarry := tmp >> 32
		a[i] = uint32(tmp)
		carry = thisCarry
	}
}
