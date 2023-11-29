// Reference: https://github.com/openssh/openssh-portable/blob/V_9_0_P1/sc25519.c
package bip32

import (
	"crypto/subtle"
	"encoding/hex"
)

type Scalar = [32]byte

var nBytes, _ = hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
var n = Scalar(nBytes)

// (a + b) mod n
// constant-time
func scAdd(a Scalar, b Scalar) Scalar {
	var carry byte
	for i := len(a) - 1; i >= 0; i-- {
		thisCarry, sum := sumTwoBytes(a[i], b[i], carry)
		a[i] = sum
		carry = thisCarry
	}
	conditionallySubtract(int(carry), &a, n)
	scReduce(&a)
	return a
}

// reduction mod n
// constant-time
func scReduce(a *Scalar) {
	cmp := compareBytes(*a, n)
	isGe := subtle.ConstantTimeLessOrEq(0, cmp)
	conditionallySubtract(isGe, a, n)
}

// if cond == 1, a -= n. otherwise, a is unchanged.
// if cond is another value, the result is undefined.
func conditionallySubtract(cond int, a *[32]byte, n [32]byte) {
	sub := *a
	inPlaceSubtract(&sub, n)
	for i := 0; i < len(a); i++ {
		a[i] = byte(subtle.ConstantTimeSelect(cond, int(sub[i]), int(a[i])))
	}
}

// if cond == 1, a -= n. otherwise, a is unchanged.
// if cond is another value, the result is undefined.
func conditionallyAdd(cond int, a *[32]byte, n [32]byte) {
	sub := *a
	inPlaceAdd(&sub, n)
	for i := 0; i < len(a); i++ {
		a[i] = byte(subtle.ConstantTimeSelect(cond, int(sub[i]), int(a[i])))
	}
}

func inPlaceAdd(a *[32]byte, b [32]byte) {
	var carry byte
	for i := len(a) - 1; i >= 0; i-- {
		thisCarry, sum := sumTwoBytes(a[i], b[i], carry)
		a[i] = sum
		carry = thisCarry
	}
}

func inPlaceSubtract(a *[32]byte, b [32]byte) {
	var borrow byte = 1
	for i := len(a) - 1; i >= 0; i-- {
		thisBorrow, diff := subTwoBytes(a[i], b[i], borrow)
		a[i] = diff
		borrow = thisBorrow
	}
}

func sumTwoBytes(a byte, b byte, c byte) (byte, byte) {
	sum := int(a) + int(b) + int(c)
	return byte(sum >> 8), byte(sum & 0xff)
}

func subTwoBytes(a byte, b byte, borrow byte) (byte, byte) {
	sum := 255 + int(a) - int(b) + int(borrow)
	return byte(sum >> 8), byte(sum & 0xff)
}

// -1: lt, 0: eq, 1: gt
func compareBytes(a Scalar, b Scalar) int {
	result := 0
	for i := 0; i < len(a); i++ {
		le := subtle.ConstantTimeLessOrEq(int(a[i]), int(b[i]))
		eq := subtle.ConstantTimeByteEq(a[i], b[i])
		now := subtle.ConstantTimeSelect(le, eq-1, 1)
		result = subtle.ConstantTimeSelect(result*result, result, now)
	}
	return result
}
