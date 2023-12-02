package bip32

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"

	//lint:ignore SA1019 we want to implement a bip32-oriented package, so using RIPEMD-160 is inevitable.
	"golang.org/x/crypto/ripemd160"
)

func uint32ToBytes(a uint32) [4]byte {
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], a)
	return result
}

func hmacThing(chainCode [32]byte, keyElement [33]byte, childIdx uint32) [64]byte {
	hash := hmac.New(sha512.New, chainCode[:])
	_, _ = hash.Write(keyElement[:])
	value := uint32ToBytes(childIdx)
	_, _ = hash.Write(value[:])
	return [64]byte(hash.Sum(nil))
}

func hash160(a []byte) []byte {
	hash := ripemd160.New()
	intermediate := sha256.Sum256(a)
	hash.Write(intermediate[:])
	return hash.Sum(nil)
}

func checksum(a []byte) [4]byte {
	intermediate := sha256.Sum256(a)
	hash := sha256.Sum256(intermediate[:])
	return [4]byte(hash[:4])
}
