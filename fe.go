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
	// TODO: make it constant-time
	aBig := big.NewInt(0).SetBytes(a[:])
	bBig := big.NewInt(0).SetBytes(b[:])
	aBig.Mul(aBig, bBig)
	aBig.Rem(aBig, pBig)
	var result FE
	aBig.FillBytes(result[:])
	return result
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
