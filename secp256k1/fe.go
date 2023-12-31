package secp256k1

import (
	"crypto/subtle"
	"encoding/hex"
	"math/big"
)

var pBytes, _ = hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
var P = [32]byte(pBytes) // P is the order of the defining field F_p, namely 2^256 - 2^32 - 977.
var pBig = big.NewInt(0).SetBytes(pBytes)

// fe represents an integer mod P. Its zero value represents 0 mod P.
type fe [32]byte

// feMul returns (a * b) mod P.
// It runs in constant-time.
func feMul(a fe, b fe) fe {
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
	sum := fe{}
	for i := 0; i < 32; i++ {
		sum[i] = byte(t[i+31])
	}
	feReduce(&sum)
	return sum
}

// feVartimeMul returns (a * b) mod P.
// It runs in constant-time.
func feVartimeMul(a fe, b fe) fe {
	aBig := big.NewInt(0).SetBytes(a[:])
	bBig := big.NewInt(0).SetBytes(b[:])
	aBig.Mul(aBig, bBig)
	aBig.Rem(aBig, pBig)
	var result fe
	aBig.FillBytes(result[:])
	return result
}

func feSquare(a fe) fe {
	return feMul(a, a)
}

// feInv gets the inverse of a. It retuns 0 if `a == 0`.
//
// This function is about 400x as slow as `feVartimeInv`.
// If you don't need constant-time property, you should use `feVartimeInv` instead.
func feInv(a fe) fe {
	// ^(p-2)
	exp := P
	exp[31] -= 2
	var prod fe
	prod[31] = 1
	current := a
	for i := 0; i < 256; i++ {
		// It's totally fine to branch with exp[_] because it's public.
		if (exp[31-i/8] & (1 << (i % 8))) != 0 {
			prod = feMul(prod, current)
		}
		current = feMul(current, current)
	}
	return prod
}

func feVartimeInv(a fe) fe {
	aBig := big.NewInt(0).SetBytes(a[:])
	aBig.ModInverse(aBig, pBig)
	var result fe
	aBig.FillBytes(result[:])
	return result
}

// (a + b) mod p
//
// constant-time
func feAdd(a fe, b fe) fe {
	var carry byte
	for i := len(a) - 1; i >= 0; i-- {
		thisCarry, sum := sumTwoBytes(a[i], b[i], carry)
		a[i] = sum
		carry = thisCarry
	}
	conditionallySubtract(int(carry), (*[32]byte)(&a), P)
	feReduce(&a)
	return a
}

// (a - b) mod p
//
// constant-time
func feSub(a fe, b fe) fe {
	var borrow byte = 1
	for i := len(a) - 1; i >= 0; i-- {
		thisBorrow, diff := subTwoBytes(a[i], b[i], borrow)
		a[i] = diff
		borrow = thisBorrow
	}
	conditionallyAdd(int(borrow^1), (*[32]byte)(&a), P)
	return a
}

func feModSqrt(a fe) fe {
	// ^((p+1)/4)
	exp := P
	exp[31] += 1
	var prod fe
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

// reduction mod p
// constant-time
func feReduce(a *fe) {
	cmp := CompareBytes([32]byte(*a), P)
	isGe := subtle.ConstantTimeLessOrEq(0, cmp)
	conditionallySubtract(isGe, (*[32]byte)(a), P)
}

// Returns a < p, runs in constant-time.
func feIsValid(a fe) int {
	cmp := CompareBytes([32]byte(a), P)
	return subtle.ConstantTimeEq(int32(cmp), -1)
}
