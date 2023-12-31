package secp256k1

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModSqrt(t *testing.T) {
	var four, two fe
	four[31] = 4
	two[31] = 2
	result := feModSqrt(four)
	assert.Equal(t, two, result)
}

func TestSub0(t *testing.T) {
	var four, two fe
	four[31] = 4
	two[31] = 2
	result := feSub(four, two)
	assert.Equal(t, two, result)
}

func TestSub1(t *testing.T) {
	var four, two fe
	four[31] = 4
	two[31] = 2
	result := feSub(two, four)
	pMinus2 := fe(P)
	pMinus2[31] -= 2
	assert.Equal(t, pMinus2, result)
}

func TestSub2(t *testing.T) {
	var two fe
	two[31] = 2
	result := feSub(two, two)
	assert.Equal(t, *new(fe), result)
}

func TestFEMul0(t *testing.T) {
	var value fe
	value[31] = 2
	expected := feVartimeMul(value, value)
	actual := feMul(value, value)
	assert.Equal(t, expected, actual)
}

func TestFEMul1(t *testing.T) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := fe(valueBytes)
	expected := feVartimeMul(value, value)
	actual := feMul(value, value)
	assert.Equal(t, expected, actual)
}

func TestFEInv0(t *testing.T) {
	var value fe
	value[31] = 2
	expected := feVartimeInv(value)
	actual := feInv(value)
	assert.Equal(t, expected, actual)
}

func TestFEInv1(t *testing.T) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := fe(valueBytes)
	expected := feVartimeInv(value)
	actual := feInv(value)
	assert.Equal(t, expected, actual)
}

func BenchmarkMul_ConstantTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := fe(valueBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feMul(value, value)
	}
}

func BenchmarkMul_VariableTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := fe(valueBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feVartimeMul(value, value)
	}
}

func BenchmarkInv_ConstantTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := fe(valueBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feInv(value)
	}
}

func BenchmarkInv_VariableTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := fe(valueBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feVartimeInv(value)
	}
}
