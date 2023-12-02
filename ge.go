// Reference: https://github.com/openssh/openssh-portable/blob/V_9_0_P1/ge25519.c
package bip32

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"

	btcutil "github.com/FactomProject/btcutilecc"
)

var ErrorInvalidPoint = errors.New("invalid point on secp256k1")

type Compressed = [33]byte

var (
	gxBytes, _    = hex.DecodeString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	gyBytes, _    = hex.DecodeString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	gx         FE = [32]byte(gxBytes)
	gy         FE = [32]byte(gyBytes)
)

// Point retains a point in a Jacobian coordinate
type Point struct {
	x FE
	y FE
	z FE
}

var zero, one FE

func init() {
	one[31] = 1
}

func uncompress(a Compressed) (*Point, error) {
	x := [32]byte(a[1:])
	// We are in error condition, this can be an early return
	// assert a[0] == 2 or a[0] == 3
	if (a[0] & 0xfe) != 2 {
		return nil, ErrorInvalidPoint
	}
	// assert x < p
	if feIsValid(x) != 1 {
		return nil, ErrorInvalidPoint
	}
	// y^2 = x^3 + 7
	var seven FE
	seven[31] = 7
	xCube := feMul(x, x)
	xCube = feMul(xCube, x)
	ySquare := feAdd(xCube, seven)
	y := feModSqrt(ySquare)
	// checks if ySquare was a quadratic residue by computing y * y == ySquare
	ySquare2 := feMul(y, y)
	if subtle.ConstantTimeCompare(ySquare[:], ySquare2[:]) != 1 {
		return nil, ErrorInvalidPublicKey
	}
	// y != 0 always holds, so (-y) mod p = p - y always holds
	negY := p
	inPlaceSubtract(&negY, y)
	// Check if the sign is correct
	diff := int((y[31] & 1) ^ (a[0] & 1))
	for i := 0; i < len(y); i++ {
		y[i] = byte(subtle.ConstantTimeSelect(diff, int(negY[i]), int(y[i])))
	}
	return &Point{x: x, y: y, z: one}, nil
}

func compress(p *Point) Compressed {
	var result [33]byte
	zInv := feInv(p.z)
	z2 := feSquare(zInv)
	z3 := feMul(z2, zInv)
	x := feMul(p.x, z2)
	y := feMul(p.y, z3)
	result[0] = byte(subtle.ConstantTimeSelect(int(y[31]&1), 0x03, 0x02))
	copy(result[1:], x[:])
	return result
}

func geAdd(a *Point, b *Point) *Point {
	sum1 := geDouble(a)
	sum2 := geAddDistinct(a, b)
	cond := subtle.ConstantTimeCompare(sum2.x[:], zero[:])
	cond &= subtle.ConstantTimeCompare(sum2.y[:], zero[:])
	cond &= subtle.ConstantTimeCompare(sum2.z[:], zero[:])
	return choicePoint(cond, sum1, sum2)
}

func geDouble(p *Point) *Point {
	// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
	a := feSquare(p.x)
	b := feSquare(p.y)
	c := feSquare(b)
	d := feSub(feSquare(feAdd(p.x, b)), feAdd(a, c))
	d = feAdd(d, d)
	e := feAdd(a, feAdd(a, a))
	f := feSquare(e)
	x3 := feSub(f, feAdd(d, d))
	y3 := feMul(e, feSub(d, x3))
	tmp := feAdd(c, c)
	tmp = feAdd(tmp, tmp)
	tmp = feAdd(tmp, tmp)
	y3 = feSub(y3, tmp)
	z3 := feMul(p.y, p.z)
	z3 = feAdd(z3, z3)
	return &Point{x: x3, y: y3, z: z3}
}

// If a = b != O, this function returns (0, 0, 0), which is invalid.
func geAddDistinct(a *Point, b *Point) *Point {
	aIsZero := subtle.ConstantTimeCompare(a.z[:], zero[:])
	bIsZero := subtle.ConstantTimeCompare(b.z[:], zero[:])
	// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
	z1z1 := feSquare(a.z)
	z2z2 := feSquare(b.z)
	u1 := feMul(a.x, z2z2)
	u2 := feMul(b.x, z1z1)
	s1 := feMul(a.y, feMul(b.z, z2z2))
	s2 := feMul(b.y, feMul(a.z, z1z1))
	h := feSub(u2, u1)
	i := feAdd(h, h)
	i = feSquare(i)
	j := feMul(h, i)
	r := feSub(s2, s1)
	r = feAdd(r, r)
	v := feMul(u1, i)
	x3 := feSquare(r)
	x3 = feSub(x3, j)
	x3 = feSub(x3, feAdd(v, v))
	y3 := feMul(r, feSub(v, x3))
	tmp := feMul(s1, j)
	y3 = feSub(y3, feAdd(tmp, tmp))
	z3 := feSquare(feAdd(a.z, b.z))
	z3 = feSub(z3, z1z1)
	z3 = feSub(z3, z2z2)
	z3 = feMul(z3, h)
	p := &Point{x: x3, y: y3, z: z3}
	return choicePoint(aIsZero, b, choicePoint(bIsZero, a, p))
}

func vartimePoint(n Scalar) *Point {
	curve := btcutil.Secp256k1()
	x, y := curve.ScalarBaseMult(n[:])
	var xBytes, yBytes [32]byte
	x.FillBytes(xBytes[:])
	y.FillBytes(yBytes[:])
	return &Point{x: xBytes, y: yBytes, z: one}
}

func gePoint(n Scalar) *Point {
	current := &Point{x: gx, y: gy, z: one}
	prod := &Point{x: one, y: one}
	for i := 0; i < 256; i++ {
		prodCurrent := geAdd(prod, current)
		cond := int(n[31-i/8]>>(i%8)) & 1
		prod = choicePoint(cond, prodCurrent, prod)
		current = geAdd(current, current)
	}
	return prod
}

func choicePoint(cond int, one *Point, zero *Point) *Point {
	var p Point
	for j := 0; j < len(one.x); j++ {
		p.x[j] = byte(subtle.ConstantTimeSelect(cond, int(one.x[j]), int(zero.x[j])))
		p.y[j] = byte(subtle.ConstantTimeSelect(cond, int(one.y[j]), int(zero.y[j])))
		p.z[j] = byte(subtle.ConstantTimeSelect(cond, int(one.z[j]), int(zero.z[j])))
	}
	return &p
}
