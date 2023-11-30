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

func BenchmarkEncode_ConstantTime_Long(b *testing.B) {
	var data [82]byte
	data[0] = 1
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(data[:], 111)
	}
}

func BenchmarkEncode_ConstantTime_Short(b *testing.B) {
	var data [82]byte
	data[41] = 1
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(data[:], 111)
	}
}

func BenchmarkEncode_VariableTime_Long(b *testing.B) {
	var data [82]byte
	data[0] = 1
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VartimeEncode(data[:], 111)
	}
}

func BenchmarkEncode_VariableTime_Short(b *testing.B) {
	var data [82]byte
	data[41] = 1
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VartimeEncode(data[:], 111)
	}
}
