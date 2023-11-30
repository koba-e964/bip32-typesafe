package bip32

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGEAdd(t *testing.T) {
	base := &Point{x: gx, y: gy, z: one}
	zero := &Point{x: one, y: one}
	result := geAdd(base, zero)
	assert.Equal(t, base, result)
}

func TestGEPoint(t *testing.T) {
	var two FE
	two[31] = 2
	expected := compress(vartimePoint(two))
	result := compress(gePoint(two))
	assert.Equal(t, expected, result)
}
