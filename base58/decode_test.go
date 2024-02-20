package base58

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	raw5KB     = bytes.Repeat([]byte{0xff}, 5000)
	encoded5KB = Encode(raw5KB, 6923)
)

func TestDecode0(t *testing.T) {
	// A case in https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2012-January/001039.html
	hex, _ := hex.DecodeString("801111111111111111111111111111111111111111111111111111111111111111e5ce7258")
	encoded := "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh"
	var outputConstant, outputVariable [37]byte
	Decode(encoded, outputConstant[:])
	assert.Equal(t, hex, outputConstant[:])
	VartimeDecode(encoded, outputVariable[:])
	assert.Equal(t, hex, outputVariable[:])
}

func BenchmarkDecode_ConstantTime(b *testing.B) {
	encoded := "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh"
	var outputConstant [37]byte
	b.SetBytes(int64(len(encoded)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decode(encoded, outputConstant[:])
	}
}
func BenchmarkDecode_VariableTime(b *testing.B) {
	encoded := "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh"
	var outputConstant [37]byte
	b.SetBytes(int64(len(encoded)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VartimeDecode(encoded, outputConstant[:])
	}
}

// Reference: https://github.com/btcsuite/btcd/blob/13152b35e191385a874294a9dbc902e48b1d71b0/btcutil/base58/base58bench_test.go
func BenchmarkDecode_ConstantTime_5K(b *testing.B) {
	buf := make([]byte, 5000)
	b.SetBytes(int64(len(encoded5KB)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decode(encoded5KB, buf)
	}
}

func BenchmarkDecode_VariableTime_5K(b *testing.B) {
	buf := make([]byte, 5000)
	b.SetBytes(int64(len(encoded5KB)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VartimeDecode(encoded5KB, buf)
	}
}
