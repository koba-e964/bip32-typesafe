package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGEAdd(t *testing.T) {
	base := &Point{x: gx, y: gy, z: one}
	zero := &Point{x: one, y: one}
	result := GEAdd(base, zero)
	assert.Equal(t, base, result)
}

func TestGEPoint0(t *testing.T) {
	var two Scalar
	two[31] = 2
	expected := GEVartimePoint(two).Compress()
	result := GEPoint(two).Compress()
	assert.Equal(t, expected, result)
}

func TestGEPoint1(t *testing.T) {
	expected := zero
	result := GEPoint(Order)
	assert.Equal(t, expected, result.z)
}

func TestGEPoint2(t *testing.T) {
	exp := Order
	exp[31] += 1
	expected := GEPoint(Scalar(one)).Compress()
	result := GEPoint(exp).Compress()
	assert.Equal(t, expected, result)
}
