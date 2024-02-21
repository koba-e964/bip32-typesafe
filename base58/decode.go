package base58

import (
	"crypto/subtle"
	"math/big"
)

func vartimeCharToIndex(char byte) int {
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
	return int(index)
}

// VartimeDecode writes into output.
//
// If the resulting integer doesn't fit in output,
// the higher part will be truncated.
//
// This function does not have a constant-time guarantee, but it is faster than Decode.
func VartimeDecode(encoded string, output []byte) {
	tmp := big.NewInt(0)
	targetLen := len(output)

	// Using technique in https://github.com/btcsuite/btcd/blob/13152b35e191385a874294a9dbc902e48b1d71b0/btcutil/base58/base58.go#L34-L49
	baseAccum := int64(1)
	lenAccum := 0
	addendum := int64(0)

	for i := 0; i < len(encoded); i++ {
		char := encoded[i]
		index := vartimeCharToIndex(char)
		baseAccum *= 58
		lenAccum++
		addendum = addendum*58 + int64(index)
		if lenAccum == 10 {
			tmp.Mul(tmp, big.NewInt(baseAccum)).Add(tmp, big.NewInt(addendum))
			baseAccum = 1
			lenAccum = 0
			addendum = 0
		}
	}
	if lenAccum > 0 {
		tmp.Mul(tmp, big.NewInt(baseAccum)).Add(tmp, big.NewInt(addendum))
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
	multiplier := 1
	addendum := 0
	lenUnprocessed := 0
	maybeNonzeroBits := 0
	for i := 0; i < len(encoded); i++ {
		char := int(encoded[i])
		index := char - '1'                                                                           // [0,9): '1'..'9'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('A', char), char-'A'+9, index)  // [9,17): 'A'..'H'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('J', char), char-'J'+17, index) // [17,22): 'J'..'N'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('P', char), char-'P'+22, index) // [22,33): 'P'..'Z'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('a', char), char-'a'+33, index) // [33,44): 'a'..'k'
		index = subtle.ConstantTimeSelect(subtle.ConstantTimeLessOrEq('m', char), char-'m'+44, index) // [44,58): 'm'..'z'
		multiplier *= 58
		addendum = addendum*58 + index
		lenUnprocessed++
		maybeNonzeroBits += 6 // 58 < 2^6
		if lenUnprocessed == 5 {
			inplaceMulAdd(tmp[len(tmp)-min(len(tmp), (maybeNonzeroBits+7)/8):], multiplier, addendum)
			multiplier = 1
			addendum = 0
			lenUnprocessed = 0
		}
	}
	if lenUnprocessed > 0 {
		inplaceMulAdd(tmp, multiplier, addendum)
	}
	for i := 0; i < targetLen; i++ {
		output[targetLen-1-i] = byte(tmp[len(tmp)-1-i/4] >> (8 * (i % 4)))
	}
}

func inplaceMulAdd(a []uint32, multiplier int, addendum int) {
	carry := uint64(addendum)
	for i := len(a) - 1; i >= 0; i-- {
		tmp := uint64(a[i])*uint64(multiplier) + carry
		thisCarry := tmp >> 32
		a[i] = uint32(tmp)
		carry = thisCarry
	}
}
