package bip32

import (
	"encoding/hex"
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

func TestFEMul(t *testing.T) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := FE(valueBytes)
	expected := feVartimeMul(value, value)
	actual := feMul(value, value)
	assert.Equal(t, expected, actual)
}

func BenchmarkMul_ConstantTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := FE(valueBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feMul(value, value)
	}
}

func BenchmarkMul_VariableTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := FE(valueBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feVartimeMul(value, value)
	}
}
