package bip32

import (
	"crypto/subtle"
	"encoding/hex"
	"math/big"
)

var pBytes, _ = hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
var p = FE(pBytes)
var pBig = big.NewInt(0).SetBytes(pBytes)

type FE = [32]byte

func feMul(a FE, b FE) FE {
	// Using technique used in https://github.com/openssh/openssh-portable/blob/V_9_1_P1/fe25519.c#L196-L211
	// a, b are in big-endian, so indices in the original implementation must be reversed.
	var t [63]uint32
	for i := 0; i < 32; i++ {
		for j := 0; j < 32; j++ {
			t[i+j] += uint32(a[i]) * uint32(b[j])
		}
	}
	for i := 32; i < 63; i++ {
		v := t[i-32]
		t[i-4] += v
		t[i-1] += 3 * v
		t[i] += 209 * v
	}
	// now t[i] < 256 * (2 * 209 + 1)
	// Using technique used in https://github.com/openssh/openssh-portable/blob/V_9_1_P1/fe25519.c#L63-L81
	for rep := 0; rep < 2; rep++ {
		v := t[31] >> 8
		t[31] &= 0xff
		t[58] += v
		t[61] += 3 * v
		t[62] += 209 * v

		for i := 62; i >= 32; i-- {
			u := t[i] >> 8
			t[i-1] += u
			t[i] &= 0xff
		}
	}
	sum := FE{}
	for i := 0; i < 32; i++ {
		sum[i] = byte(t[i+31])
	}
	feReduce(&sum)
	return sum
}

func feVartimeMul(a FE, b FE) FE {
	aBig := big.NewInt(0).SetBytes(a[:])
	bBig := big.NewInt(0).SetBytes(b[:])
	aBig.Mul(aBig, bBig)
	aBig.Rem(aBig, pBig)
	var result FE
	aBig.FillBytes(result[:])
	return result
}

func feSquare(a FE) FE {
	// TODO: faster than feMul
	return feMul(a, a)
}

func feInv(a FE) FE {
	// TODO: make it constant-time
	aBig := big.NewInt(0).SetBytes(a[:])
	aBig.ModInverse(aBig, pBig)
	var result FE
	aBig.FillBytes(result[:])
	return result
}

// (a + b) mod p
//
// constant-time
func feAdd(a FE, b FE) FE {
	var carry byte
	for i := len(a) - 1; i >= 0; i-- {
		thisCarry, sum := sumTwoBytes(a[i], b[i], carry)
		a[i] = sum
		carry = thisCarry
	}
	conditionallySubtract(int(carry), &a, p)
	feReduce(&a)
	return a
}

// (a - b) mod p
//
// constant-time
func feSub(a FE, b FE) FE {
	var borrow byte = 1
	for i := len(a) - 1; i >= 0; i-- {
		thisBorrow, diff := subTwoBytes(a[i], b[i], borrow)
		a[i] = diff
		borrow = thisBorrow
	}
	conditionallyAdd(int(borrow^1), &a, p)
	return a
}

func feModSqrt(a FE) FE {
	// ^((p+1)/4)
	exp := p
	exp[31] += 1
	var prod FE
	prod[31] = 1
	current := a
	for i := 2; i < 256; i++ {
		// It's totally fine to branch with exp[_] because it's public.
		if (exp[31-i/8] & (1 << (i % 8))) != 0 {
			prod = feMul(prod, current)
		}
		current = feMul(current, current)
	}
	return prod
}

// reduction mod n
// constant-time
func feReduce(a *FE) {
	cmp := compareBytes(*a, p)
	isGe := subtle.ConstantTimeLessOrEq(0, cmp)
	conditionallySubtract(isGe, a, p)
}

// Returns a < p, runs in constant-time.
func feIsValid(a FE) int {
	cmp := compareBytes(a, p)
	return subtle.ConstantTimeEq(int32(cmp), -1)
}

func choiceFE(cond int, one FE, zero FE) FE {
	var p FE
	for j := 0; j < len(one); j++ {
		p[j] = byte(subtle.ConstantTimeSelect(cond, int(one[j]), int(zero[j])))
	}
	return p
}
