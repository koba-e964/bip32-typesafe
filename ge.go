// Reference: https://github.com/openssh/openssh-portable/blob/V_9_0_P1/ge25519.c
package bip32

import (
	"crypto/subtle"
	"errors"
	"math/big"

	btcutil "github.com/FactomProject/btcutilecc"
)

var ErrorInvalidPoint = errors.New("invalid point on secp256k1")

type Compressed = [33]byte
type Point struct {
	x FE
	y FE
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
	return &Point{x: x, y: y}, nil
}

func compress(p *Point) Compressed {
	var result [33]byte
	result[0] = byte(subtle.ConstantTimeSelect(int(p.y[31]&1), 0x03, 0x02))
	copy(result[1:], p.x[:])
	return result
}

func geAdd(a *Point, b *Point) *Point {
	// TODO: make it constant-time
	curve := btcutil.Secp256k1()
	xa := big.NewInt(0).SetBytes(a.x[:])
	ya := big.NewInt(0).SetBytes(a.y[:])
	xb := big.NewInt(0).SetBytes(b.x[:])
	yb := big.NewInt(0).SetBytes(b.y[:])
	x, y := curve.Add(xa, ya, xb, yb)
	var xBytes, yBytes FE
	x.FillBytes(xBytes[:])
	y.FillBytes(yBytes[:])
	return &Point{x: xBytes, y: yBytes}
}

func vartimePoint(n Scalar) *Point {
	// TODO: Use a secure impl of secp256k1 or write one on my own
	// AVT VIAM INVENIAM AVT FACIAM
	curve := btcutil.Secp256k1()
	x, y := curve.ScalarBaseMult(n[:])
	var xBytes, yBytes [32]byte
	x.FillBytes(xBytes[:])
	y.FillBytes(yBytes[:])
	return &Point{x: xBytes, y: yBytes}
}
