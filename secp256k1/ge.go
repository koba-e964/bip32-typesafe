package secp256k1

// Reference: https://github.com/openssh/openssh-portable/blob/V_9_0_P1/ge25519.c
import (
	"crypto/subtle"
	"encoding/hex"
	"errors"

	btcutil "github.com/FactomProject/btcutilecc"
)

// ErrorInvalidPoint is returned when an invalid point was found. The reasons why a point is invalid include:
//   - invalid header (neither 02 nor 03)
//   - could not find the y coordinate
var ErrorInvalidPoint = errors.New("invalid point on secp256k1")

// Compressed is a compressed (33-byte, x-coordinate + y mod 2) representation of a point on secp256k1.
// Its zero value is invalid. It cannot represent the infinity (zero element).
type Compressed [33]byte

var (
	gxBytes, _    = hex.DecodeString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	gyBytes, _    = hex.DecodeString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	gx         fe = feFromBytes([32]byte(gxBytes))
	gy         fe = feFromBytes([32]byte(gyBytes))
)

// Point retains a point in projective coordinates.
//
// Two distinct representations can represent the same point,
// so you cannot simply compare two Points with == to check if they are equal.
// You need to first compress them into Compressed and then compare.
//
// Its zero value is invalid.
type Point = ProjPoint

// JacobianPoint retains a point in Jacobian coordinates.
//
// Two distinct representations can represent the same point,
// so you cannot simply compare two Points with == to check if they are equal.
// You need to first compress them into Compressed and then compare.
//
// Its zero value is invalid.
type JacobianPoint struct {
	x fe
	y fe
	z fe
}

// ProjPoint retains a point in projective coordinates.
//
// Two distinct representations can represent the same point,
// so you cannot simply compare two Points with == to check if they are equal.
// You need to first compress them into Compressed and then compare.
//
// Its zero value is invalid.
type ProjPoint struct {
	x fe
	y fe
	z fe
}

var zero, one fe
var table [256]JacobianPoint // table[i] = 2^i * G
var projTable [256]ProjPoint // projTable[i] = 2^i * G

func init() {
	one[7] = 1
	table[0] = JacobianPoint{x: gx, y: gy, z: one}
	projTable[0] = ProjPoint{x: gx, y: gy, z: one}
	for i := 1; i < 256; i++ {
		table[i] = *GEJacobianDouble(&table[i-1])
		projTable[i].GEProjAdd(&projTable[i-1], &projTable[i-1])
		projTable[i].assertValid()
	}
}

func (a Compressed) Uncompress() (*Point, error) {
	result, err := a.UncompressJacobian()
	// z = 1 always holds, so result is valid as a JacobianPoint/ProjPoint
	return (*Point)(result), err
}

func (a Compressed) UncompressJacobian() (*JacobianPoint, error) {
	x := feFromBytes([32]byte(a[1:]))
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
	var seven fe
	seven[7] = 7
	xCube := feMul(x, x)
	xCube = feMul(xCube, x)
	ySquare := feAdd(xCube, seven)
	y := feModSqrt(ySquare)
	// checks if ySquare was a quadratic residue by computing y * y == ySquare
	ySquare2 := feMul(y, y)
	if CompareUint32s(ySquare2, ySquare) != 0 {
		return nil, ErrorInvalidPoint
	}
	// y != 0 always holds, so (-y) mod p = p - y always holds
	negY := pfe
	inPlaceSubtract32((*[8]uint32)(&negY), y)
	// Check if the sign is correct
	diff := int((y[7] & 1)) ^ int((a[0] & 1))
	for i := 0; i < len(y); i++ {
		y[i] = uint32(subtle.ConstantTimeSelect(diff, int(negY[i]), int(y[i])))
	}
	return &JacobianPoint{x: x, y: y, z: one}, nil
}

func (a Compressed) UncompressProj() (*ProjPoint, error) {
	result, err := a.UncompressJacobian()
	// z = 1 always holds, so result is valid as a ProjPoint
	return (*ProjPoint)(result), err
}

// Compress returns the value in the compressed format. It runs in constant-time.
func (p *JacobianPoint) Compress() Compressed {
	var result [33]byte
	zInv := feInv(p.z)
	z2 := feSquare(zInv)
	z3 := feMul(z2, zInv)
	x := feMul(p.x, z2)
	y := feMul(p.y, z3)
	result[0] = byte(y[7]&1) | 0x02
	xBytes := x.Bytes()
	copy(result[1:], xBytes[:])
	return result
}

// Compress returns the value in the compressed format. It runs in constant-time.
func (p *ProjPoint) Compress() Compressed {
	var result [33]byte
	zInv := feInv(p.z)
	x := feMul(p.x, zInv)
	y := feMul(p.y, zInv)
	result[0] = byte(y[7]&1) | 0x02
	xBytes := x.Bytes()
	copy(result[1:], xBytes[:])
	return result
}

func (p *ProjPoint) assertValid() {
	tmp := feMul(feMul(p.y, p.y), p.z)
	tmp = feSub(tmp, feMul(feMul(p.x, p.x), p.x))
	var bconst fe
	bconst[7] = 7
	tmp = feSub(tmp, feMul(feMul(p.z, p.z), feMul(p.z, bconst)))
	if CompareUint32s(tmp, zero) != 0 {
		panic("invalid point")
	}
}

// GEAdd computes a + b. It runs in constant-time.
func (p *Point) GEAdd(a *Point, b *Point) {
	p.GEProjAdd(a, b)
}

// GEJacobianAdd computes a + b. It runs in constant-time.
func GEJacobianAdd(a *JacobianPoint, b *JacobianPoint) *JacobianPoint {
	// 13 feMul + 10 feSquare + 15 feAdd + 12 feSub
	sum1 := GEJacobianDouble(a)
	sum2 := geAddDistinct(a, b)
	cond := CompareUint32s(sum2.x, zero) & 1
	cond |= CompareUint32s(sum2.y, zero) & 1
	cond |= CompareUint32s(sum2.z, zero) & 1
	sum1.choiceJacobianPoint(cond^1, sum1, sum2)
	return sum1
}

// GEProjAdd uses Algorithm 7 in https://eprint.iacr.org/2015/1060
func (p *ProjPoint) GEProjAdd(a *ProjPoint, b *ProjPoint) {
	// 12 feMul + 2 feMul21 + 14 feAdd + 5 feSub
	t0 := feMul(a.x, b.x)
	t1 := feMul(a.y, b.y)
	t2 := feMul(a.z, b.z)
	t3 := feAdd(a.x, a.y)
	t4 := feAdd(b.x, b.y)
	t3 = feMul(t3, t4)
	t4 = feAdd(t0, t1)
	t3 = feSub(t3, t4)
	t4 = feAdd(a.y, a.z)
	x3 := feAdd(b.y, b.z)
	t4 = feMul(t4, x3)
	x3 = feAdd(t1, t2)
	t4 = feSub(t4, x3)
	x3 = feAdd(a.x, a.z)
	y3 := feAdd(b.x, b.z)
	x3 = feMul(x3, y3)
	y3 = feAdd(t0, t2)
	y3 = feSub(x3, y3)
	x3 = feAdd(t0, t0)
	t0 = feAdd(x3, t0)
	t2 = feMul21(t2)
	z3 := feAdd(t1, t2)
	t1 = feSub(t1, t2)
	y3 = feMul21(y3)
	x3 = feMul(t4, y3)
	t2 = feMul(t3, t1)
	x3 = feSub(t2, x3)
	y3 = feMul(y3, t0)
	t1 = feMul(t1, z3)
	y3 = feAdd(t1, y3)
	t0 = feMul(t0, t3)
	z3 = feMul(z3, t4)
	z3 = feAdd(z3, t0)
	p.x = x3
	p.y = y3
	p.z = z3
}

// GEDouble computes 2*arg. It runs in constant-time.
func (p *Point) GEDouble(arg *Point) {
	p.GEProjDouble(arg)
}

// GEJacobianDouble computes 2p. It runs in constant-time.
func GEJacobianDouble(p *JacobianPoint) *JacobianPoint {
	// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
	// 2 feMul + 5 feSquare + 10 feAdd + 4 feSub
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
	return &JacobianPoint{x: x3, y: y3, z: z3}
}

// GEProjDouble computes 2*arg. It runs in constant-time.
func (p *ProjPoint) GEProjDouble(arg *ProjPoint) {
	// Specialization of GEProjAdd with a == b to use feSquare where possible.
	t0 := feSquare(arg.x)
	t1 := feSquare(arg.y)
	t2 := feSquare(arg.z)
	t3 := feAdd(arg.x, arg.y)
	t3 = feSquare(t3)
	t4 := feAdd(t0, t1)
	t3 = feSub(t3, t4)
	t4 = feAdd(arg.y, arg.z)
	t4 = feSquare(t4)
	x3 := feAdd(t1, t2)
	t4 = feSub(t4, x3)
	x3 = feAdd(arg.x, arg.z)
	y3 := x3
	x3 = feSquare(x3)
	y3 = feAdd(t0, t2)
	y3 = feSub(x3, y3)
	x3 = feAdd(t0, t0)
	t0 = feAdd(x3, t0)
	t2 = feMul21(t2)
	z3 := feAdd(t1, t2)
	t1 = feSub(t1, t2)
	y3 = feMul21(y3)
	x3 = feMul(t4, y3)
	t2 = feMul(t3, t1)
	x3 = feSub(t2, x3)
	y3 = feMul(y3, t0)
	t1 = feMul(t1, z3)
	y3 = feAdd(t1, y3)
	t0 = feMul(t0, t3)
	z3 = feMul(z3, t4)
	z3 = feAdd(z3, t0)
	p.x = x3
	p.y = y3
	p.z = z3
}

// If a = b != O, this function returns (0, 0, 0), which is invalid.
func geAddDistinct(a *JacobianPoint, b *JacobianPoint) *JacobianPoint {
	// 11 feMul + 5 feSquare + 5 feAdd + 8 feSub
	aIsZero := CompareUint32s(a.z, zero) ^ 1
	bIsZero := CompareUint32s(b.z, zero) ^ 1
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
	p := &JacobianPoint{x: x3, y: y3, z: z3}
	p.choiceJacobianPoint(bIsZero, a, p)
	p.choiceJacobianPoint(aIsZero, b, p)
	return p
}

// GEVartimePoint computes n G where G is the base point.
// It does not have a constant-time guarantee.
func GEVartimePoint(n Scalar) *Point {
	// For return values of GEVartimeJacobianPoint z = 1 always holds, so it is valid as a JacobianPoint/ProjPoint
	return (*Point)(GEVartimeJacobianPoint(n))
}

func GEVartimeJacobianPoint(n Scalar) *JacobianPoint {
	curve := btcutil.Secp256k1()
	x, y := curve.ScalarBaseMult(n[:])
	var xBytes, yBytes [32]byte
	x.FillBytes(xBytes[:])
	y.FillBytes(yBytes[:])
	return &JacobianPoint{x: feFromBytes(xBytes), y: feFromBytes(yBytes), z: one}
}

func GEVartimeProjPoint(n Scalar) *ProjPoint {
	// For return values of GEVartimeJacobianPoint z = 1 always holds, so it is valid as a ProjPoint
	return (*ProjPoint)(GEVartimeJacobianPoint(n))
}

// GEPoint computes n G where G is the base point. It runs in constant-time.
func (p *Point) GEPoint(n Scalar) {
	p.GEProjPoint(n)
}

func GEJacobianPoint(n Scalar) *JacobianPoint {
	prod := &JacobianPoint{x: one, y: one}
	for i := 0; i < 256; i++ {
		prodCurrent := GEJacobianAdd(prod, &table[i])
		cond := int(n[31-i/8]>>(i%8)) & 1
		prod.choiceJacobianPoint(cond, prodCurrent, prod)
	}
	return prod
}

func (p *ProjPoint) GEProjPoint(n Scalar) {
	*p = ProjPoint{y: one}
	var prodCurrent ProjPoint
	for i := 0; i < 256; i++ {
		prodCurrent.GEProjAdd(p, &projTable[i])
		cond := int(n[31-i/8]>>(i%8)) & 1
		p.choiceProjPoint(cond, &prodCurrent, p)
	}
}

func (p *JacobianPoint) choiceJacobianPoint(cond int, one *JacobianPoint, zero *JacobianPoint) {
	for j := 0; j < len(one.x); j++ {
		p.x[j] = uint32(subtle.ConstantTimeSelect(cond, int(one.x[j]), int(zero.x[j])))
		p.y[j] = uint32(subtle.ConstantTimeSelect(cond, int(one.y[j]), int(zero.y[j])))
		p.z[j] = uint32(subtle.ConstantTimeSelect(cond, int(one.z[j]), int(zero.z[j])))
	}
}

func (p *ProjPoint) choiceProjPoint(cond int, one *ProjPoint, zero *ProjPoint) {
	for j := 0; j < len(one.x); j++ {
		p.x[j] = uint32(subtle.ConstantTimeSelect(cond, int(one.x[j]), int(zero.x[j])))
		p.y[j] = uint32(subtle.ConstantTimeSelect(cond, int(one.y[j]), int(zero.y[j])))
		p.z[j] = uint32(subtle.ConstantTimeSelect(cond, int(one.z[j]), int(zero.z[j])))
	}
}
