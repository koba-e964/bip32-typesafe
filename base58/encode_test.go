package base58

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncode0(t *testing.T) {
	for firstByte := 0; firstByte < 256; firstByte++ {
		var data [82]byte
		data[0] = byte(firstByte)
		copyData := data
		expected := VartimeEncode(data[:], 111)
		assert.Equal(t, copyData, data)
		actual := Encode(data[:], 111)
		assert.Equal(t, expected, actual)
		assert.Equal(t, copyData, data)
	}
}

func TestEncode1(t *testing.T) {
	data := []byte{1}
	// Asserts if resultLen is very long, it does not panic.
	Encode(data, 100)
}

func TestEncode2(t *testing.T) {
	// A case in https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2012-January/001039.html
	hex, _ := hex.DecodeString("801111111111111111111111111111111111111111111111111111111111111111e5ce7258")
	encoded := "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh"
	actual := Encode(hex, 51)
	assert.Equal(t, encoded, actual)
}

func BenchmarkEncode_ConstantTime_Long(b *testing.B) {
	var data [82]byte
	data[0] = 1
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(data[:], 111)
	}
}

func BenchmarkEncode_ConstantTime_Short(b *testing.B) {
	var data [82]byte
	data[41] = 1
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(data[:], 111)
	}
}

func BenchmarkEncode_VariableTime_Long(b *testing.B) {
	var data [82]byte
	data[0] = 1
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VartimeEncode(data[:], 111)
	}
}

func BenchmarkEncode_VariableTime_Short(b *testing.B) {
	var data [82]byte
	data[41] = 1
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VartimeEncode(data[:], 111)
	}
}

func BenchmarkEncode_ConstantTime_5K(b *testing.B) {
	data := make([]byte, 5000)
	data[0] = 1
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(data[:], 6829)
	}
}

func BenchmarkEncode_VariableTime_5K(b *testing.B) {
	data := make([]byte, 5000)
	data[0] = 1
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VartimeEncode(data[:], 6829)
	}
}
