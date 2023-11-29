// Reference: https://github.com/openssh/openssh-portable/blob/V_9_0_P1/ge25519.c
package bip32

import (
	"crypto/subtle"
	"errors"

	btcutil "github.com/FactomProject/btcutilecc"
)

var ErrorInvalidPoint = errors.New("invalid point on secp256k1")

type Compressed = [33]byte

// Point retains a point in a Jacobian coordinate
type Point struct {
	x FE
	y FE
	z FE
}

var one FE

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
	return &Point{x: x3, y: y3, z: z3}
}

func vartimePoint(n Scalar) *Point {
	// TODO: Use a secure impl of secp256k1 or write one on my own
	// AVT VIAM INVENIAM AVT FACIAM
	curve := btcutil.Secp256k1()
	x, y := curve.ScalarBaseMult(n[:])
	var xBytes, yBytes [32]byte
	x.FillBytes(xBytes[:])
	y.FillBytes(yBytes[:])
	return &Point{x: xBytes, y: yBytes, z: one}
}
