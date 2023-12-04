package secp256k1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSCAdd(t *testing.T) {
	a := Scalar(Order)
	a[31] -= 1
	b := a
	b[31] -= 1
	assert.Equal(t, b, SCAdd(a, a))
}

func TestInplaceSubtract(t *testing.T) {
	var a, b Scalar
	a[31] = 4
	b[31] = 7
	inPlaceSubtract((*[32]byte)(&a), b)
	assert.Equal(t, a[0], byte(0xff))
}
