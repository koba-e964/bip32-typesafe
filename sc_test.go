package bip32

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSCAdd(t *testing.T) {
	a := n
	a[31] -= 1
	b := a
	b[31] -= 1
	assert.Equal(t, b, scAdd(a, a))
}

func TestInplaceSubtract(t *testing.T) {
	var a, b Scalar
	a[31] = 4
	b[31] = 7
	inPlaceSubtract(&a, b)
	assert.Equal(t, a[0], byte(0xff))
}
