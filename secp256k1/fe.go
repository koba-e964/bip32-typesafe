package secp256k1

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"math/bits"
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
	var t [16]uint64 // 16 * uint32
	var a32, b32 [8]uint32
	for i := 0; i < 8; i++ {
		a32[i] = binary.BigEndian.Uint32(a[i*4 : i*4+4])
		b32[i] = binary.BigEndian.Uint32(b[i*4 : i*4+4])
	}
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			hi, lo := bits.Mul32(a32[i], b32[j])
			t[i+j+1] += uint64(lo)
			t[i+j] += uint64(hi)
		}
	}

	for i := 15; i > 0; i-- {
		t[i-1] += t[i] >> 32
		t[i] &= 0xffff_ffff
	}
	for i := 8; i < 16; i++ {
		v := t[i-8]
		t[i-1] += v
		t[i] += 977 * v
	}
	// now t[i] < 2^32 * (2 * 977 + 1)
	// Using technique used in https://github.com/openssh/openssh-portable/blob/V_9_1_P1/fe25519.c#L63-L81
	// After the first reduction, the value < 2^256 + 977 * 2^225 + 977 * 2^32.
	// Reducing once more will make the value < 2^256.
	for rep := 0; rep < 2; rep++ {
		v := t[8] >> 32
		t[8] &= 0xffff_ffff
		t[14] += v
		t[15] += 977 * v

		for i := 15; i > 8; i-- {
			t[i-1] += t[i] >> 32
			t[i] &= 0xffff_ffff
		}
	}
	sum := fe{}
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(sum[i*4:i*4+4], uint32(t[i+8]))
	}
	feReduce(&sum)
	return sum
}

// feVartimeMul returns (a * b) mod P.
// This function does not have a constant-time guarantee.
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

// feInv gets the inverse of a. It returns 0 if `a == 0`.
//
// This function is about 80x as slow as `feVartimeInv`.
// If you don't need constant-time property, you should use `feVartimeInv` instead.
func feInv(a fe) fe {
	// 255 feSquare + 15 feMul
	// ^(p-2)
	// Employing technique in https://github.com/bitcoin-core/secp256k1/blob/v0.4.1/src/field_impl.h#L33-L132
	// p-2 = 2^256 - 2^32 - 979 = c_223 * 2^33 + c_22 * 2^10 + c_1 * 2^5 + c_2 * 2^2 + 1
	// where c_i = 11...11 (i times) = 2^i - 1
	// The binary representation of p-2 has 5 blocks with lengths 223, 22, 1, 2, 1.
	// We use the following addition chain:
	// [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
	var x1, x2, x3, x22, x223 fe
	x1 = a
	x2 = feMul(feSquare(x1), x1)
	// 20 feSquare + 5 feMul
	{
		x3 = feMul(feSquare(x2), x1)
		x6 := x3
		for i := 0; i < 3; i++ {
			x6 = feSquare(x6)
		}
		x6 = feMul(x6, x3)
		x9 := x6
		for i := 0; i < 3; i++ {
			x9 = feSquare(x9)
		}
		x9 = feMul(x9, x3)
		x11 := x9
		for i := 0; i < 2; i++ {
			x11 = feSquare(x11)
		}
		x11 = feMul(x11, x2)
		x22 = x11
		for i := 0; i < 11; i++ {
			x22 = feSquare(x22)
		}
		x22 = feMul(x22, x11)
	}
	// 201 feSquare + 5 feMul
	{
		x44 := x22
		for i := 0; i < 22; i++ {
			x44 = feSquare(x44)
		}
		x44 = feMul(x44, x22)
		x88 := x44
		for i := 0; i < 44; i++ {
			x88 = feSquare(x88)
		}
		x88 = feMul(x88, x44)
		x176 := x88
		for i := 0; i < 88; i++ {
			x176 = feSquare(x176)
		}
		x176 = feMul(x176, x88)
		x220 := x176
		for i := 0; i < 44; i++ {
			x220 = feSquare(x220)
		}
		x220 = feMul(x220, x44)
		x223 = x220
		for i := 0; i < 3; i++ {
			x223 = feSquare(x223)
		}
		x223 = feMul(x223, x3)
	}
	// 33 feSquare + 4 feMul
	{
		result := x223
		for i := 0; i < 23; i++ {
			result = feSquare(result)
		}
		result = feMul(result, x22)
		for i := 0; i < 5; i++ {
			result = feSquare(result)
		}
		result = feMul(result, x1)
		for i := 0; i < 3; i++ {
			result = feSquare(result)
		}
		result = feMul(result, x2)
		result = feSquare(result)
		result = feSquare(result)
		result = feMul(result, x1)
		return result
	}
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
