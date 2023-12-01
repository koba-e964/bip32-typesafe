package base58

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decode(encoded, outputConstant[:])
	}
}
func BenchmarkDecode_VariableTime(b *testing.B) {
	encoded := "5HwoXVkHoRM8sL2KmNRS217n1g8mPPBomrY7yehCuXC1115WWsh"
	var outputConstant [37]byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VartimeDecode(encoded, outputConstant[:])
	}
}
