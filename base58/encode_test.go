package base58

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncode0(t *testing.T) {
	for firstByte := 0; firstByte < 256; firstByte++ {
		var data [82]byte
		data[0] = byte(firstByte)
		expected := VartimeEncode(data[:], 111)
		actual := Encode(data[:], 111)
		assert.Equal(t, expected, actual)
	}
}
