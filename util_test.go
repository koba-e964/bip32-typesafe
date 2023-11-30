package bip32

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBase58_0(t *testing.T) {
	var data [82]byte
	data[0] = 1
	expected := vartimeBase58Encode(data)
	actual := base58Encode(data)
	assert.Equal(t, expected, actual)
}

func TestBase58_1(t *testing.T) {
	var data [82]byte
	data[0] = 2
	expected := vartimeBase58Encode(data)
	actual := base58Encode(data)
	assert.Equal(t, expected, actual)
}
