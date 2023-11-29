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
