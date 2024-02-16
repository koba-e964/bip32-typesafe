package secp256k1

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestModSqrt(t *testing.T) {
	var four, two fe
	four[7] = 4
	two[7] = 2
	result := feModSqrt(four)
	assert.Equal(t, two, result)
}

func TestSub0(t *testing.T) {
	var four, two fe
	four[7] = 4
	two[7] = 2
	result := feSub(four, two)
	assert.Equal(t, two, result)
}

func TestSub1(t *testing.T) {
	var four, two fe
	four[7] = 4
	two[7] = 2
	result := feSub(two, four)
	pMinus2 := pfe
	pMinus2[7] -= 2
	assert.Equal(t, pMinus2, result)
}

func TestSub2(t *testing.T) {
	var two fe
	two[7] = 2
	result := feSub(two, two)
	assert.Equal(t, *new(fe), result)
}

func TestSub3(t *testing.T) {
	var two fe
	two[7] = 2
	result := feSub(two, two)
	assert.Equal(t, zero, result)
}

func TestFEMul0(t *testing.T) {
	var value fe
	value[7] = 2
	expected := feVartimeMul(value, value)
	actual := feMul(value, value)
	assert.Equal(t, expected, actual)
}

func TestFEMul1(t *testing.T) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	expected := feVartimeMul(value, value)
	actual := feMul(value, value)
	assert.Equal(t, expected, actual)
}

func TestFESquare0(t *testing.T) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	expected := feVartimeMul(value, value)
	actual := feSquare(value)
	assert.Equal(t, expected, actual)
}

func TestFEMul21_0(t *testing.T) {
	valueBytes, _ := hex.DecodeString("102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f123")
	value := feFromBytes([32]byte(valueBytes))
	actual := feMul21(value)
	twentyOne := fe{}
	twentyOne[7] = 21
	expected := feVartimeMul(value, twentyOne)
	assert.Equal(t, expected, actual)
}

func TestFEInv0(t *testing.T) {
	var value fe
	value[7] = 2
	expected := feVartimeInv(value)
	actual := feInv(value)
	assert.Equal(t, expected, actual)
}

func TestFEInv1(t *testing.T) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	expected := feVartimeInv(value)
	actual := feInv(value)
	assert.Equal(t, expected, actual)
}

func BenchmarkAdd_ConstantTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feAdd(value, value)
	}
}

func BenchmarkMul_ConstantTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feMul(value, value)
	}
}

func BenchmarkMul_VariableTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feVartimeMul(value, value)
	}
}

func BenchmarkSquare_ConstantTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feSquare(value)
	}
}

func BenchmarkMul21_ConstantTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feMul21(value)
	}
}

func BenchmarkInv_ConstantTime0(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feInv(value)
	}
}

func BenchmarkInv_ConstantTime1(b *testing.B) {
	valueBytes, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f1f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feInv(value)
	}
}

func BenchmarkInv_VariableTime0(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feVartimeInv(value)
	}
}

func BenchmarkInv_VariableTime1(b *testing.B) {
	valueBytes, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f1f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feVartimeInv(value)
	}
}

func BenchmarkInv_VariableTime2(b *testing.B) {
	valueBytes, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f20")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feVartimeInv(value)
	}
}

func BenchmarkModSqrt_ConstantTime(b *testing.B) {
	valueBytes, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	value := feFromBytes([32]byte(valueBytes))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feModSqrt(value)
	}
}
