package bip32

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModSqrt(t *testing.T) {
	var four, two FE
	four[31] = 4
	two[31] = 2
	result := feModSqrt(four)
	assert.Equal(t, two, result)
}

func TestSub0(t *testing.T) {
	var four, two FE
	four[31] = 4
	two[31] = 2
	result := feSub(four, two)
	assert.Equal(t, two, result)
}

func TestSub1(t *testing.T) {
	var four, two FE
	four[31] = 4
	two[31] = 2
	result := feSub(two, four)
	pMinus2 := p
	pMinus2[31] -= 2
	assert.Equal(t, pMinus2, result)
}

func TestSub2(t *testing.T) {
	var two FE
	two[31] = 2
	result := feSub(two, two)
	assert.Equal(t, *new(FE), result)
}
