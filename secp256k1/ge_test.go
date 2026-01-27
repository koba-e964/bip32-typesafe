package secp256k1

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func suppress[T any](a T, err error) T {
	if err != nil {
		panic(err)
	}
	return a
}

func TestGEJacobianAdd(t *testing.T) {
	base := &JacobianPoint{x: gx, y: gy, z: one}
	zero := &JacobianPoint{x: one, y: one}
	result := GEJacobianAdd(base, zero)
	assert.Equal(t, base.Compress(), result.Compress())
}

func TestGEJacobianAdd_Double(t *testing.T) {
	base := &JacobianPoint{x: gx, y: gy, z: one}
	result := GEJacobianAdd(base, base)
	expected := GEJacobianDouble(base)
	assert.Equal(t, expected.Compress(), result.Compress())
}

func TestGEProjAdd(t *testing.T) {
	base := &ProjPoint{x: gx, y: gy, z: one}
	zero := &ProjPoint{y: one}
	var result ProjPoint
	result.GEProjAdd(base, zero)
	assert.Equal(t, base.Compress(), result.Compress())
}

func TestGEPoint0(t *testing.T) {
	var two Scalar
	two[31] = 2
	expected := GEVartimePoint(two).Compress()
	var point Point
	point.GEPoint(two)
	result := point.Compress()
	assert.Equal(t, expected, result)
}

func TestGEPoint1(t *testing.T) {
	expected := zero
	var point Point
	point.GEPoint(Order)
	assert.Equal(t, expected, point.z)
}

func TestGEPoint2(t *testing.T) {
	exp := Order
	exp[31] += 1
	one := Scalar{}
	one[31] = 1
	var point Point
	point.GEPoint(one)
	expected := point.Compress()
	point.GEPoint(exp)
	result := point.Compress()
	assert.Equal(t, expected, result)
}

func TestGEPoint3(t *testing.T) {
	// Test vectors: https://chuckbatson.wordpress.com/2014/11/26/secp256k1-test-vectors/
	tests := []struct {
		k      byte
		result []byte
	}{
		{k: 1, result: suppress(hex.DecodeString("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"))},
		{k: 2, result: suppress(hex.DecodeString("02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"))},
		{k: 3, result: suppress(hex.DecodeString("02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"))},
		{k: 4, result: suppress(hex.DecodeString("02E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13"))},
		{k: 5, result: suppress(hex.DecodeString("022F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4"))},
		{k: 6, result: suppress(hex.DecodeString("03FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"))},
	}
	for _, test := range tests {
		var sc Scalar
		sc[31] = test.k
		var point Point
		point.GEPoint(sc)
		result := point.Compress()
		assert.Equal(t, test.result, result[:])
	}
}

func BenchmarkGEJacobianPoint_VariableTime_Short(b *testing.B) {
	var two Scalar
	two[31] = 2
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GEVartimeJacobianPoint(two)
	}
}

func BenchmarkGEJacobianPoint_VariableTime_Long(b *testing.B) {
	var k Scalar
	for i := 0; i < len(k); i++ {
		k[i] = 0xff
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GEVartimeJacobianPoint(k)
	}
}

func BenchmarkGEJacobianPoint_ConstantTime_Short(b *testing.B) {
	var two Scalar
	two[31] = 2
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GEJacobianPoint(two)
	}
}

func BenchmarkGEJacobianPoint_ConstantTime_Long(b *testing.B) {
	var k Scalar
	for i := 0; i < len(k); i++ {
		k[i] = 0xff
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GEJacobianPoint(k)
	}
}

func BenchmarkGEProjPoint_ConstantTime_Short(b *testing.B) {
	var two Scalar
	two[31] = 2
	var p ProjPoint
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.GEProjPoint(two)
	}
}
