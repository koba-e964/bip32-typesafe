package secp256k1

// Reference: https://github.com/openssh/openssh-portable/blob/V_9_0_P1/sc25519.c
import (
	"crypto/subtle"
	"encoding/hex"
)

// Scalar represents an integer mod Order. Its zero value represents 0 mod Order.
type Scalar [32]byte

var nBytes, _ = hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
var Order = [32]byte(nBytes) // The order of secp256k1, namely 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141.

// SCAdd returns (a + b) mod Order.
// It runs in constant-time.
func SCAdd(a Scalar, b Scalar) Scalar {
	var carry byte
	for i := len(a) - 1; i >= 0; i-- {
		thisCarry, sum := sumTwoBytes(a[i], b[i], carry)
		a[i] = sum
		carry = thisCarry
	}
	conditionallySubtract(int(carry), (*[32]byte)(&a), Order)
	scReduce(&a)
	return a
}

// reduction mod Order
// constant-time
func scReduce(a *Scalar) {
	cmp := CompareBytes(*a, Order)
	isGe := subtle.ConstantTimeLessOrEq(0, cmp)
	conditionallySubtract(isGe, (*[32]byte)(a), Order)
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

// CompareBytes compares two 32-byte arrays in constant-time.
//
// The return value is one of {-1, 0, 1}.
//
//   - -1: a < b
//   - 0: a = b
//   - 1: a > b
func CompareBytes(a [32]byte, b [32]byte) int {
	result := 0
	for i := 0; i < len(a); i++ {
		le := subtle.ConstantTimeLessOrEq(int(a[i]), int(b[i]))
		eq := subtle.ConstantTimeByteEq(a[i], b[i])
		now := subtle.ConstantTimeSelect(le, eq-1, 1)
		result = subtle.ConstantTimeSelect(result*result, result, now)
	}
	return result
}
