# bip32-typesafe ![Go](https://github.com/koba-e964/bip32-typesafe/actions/workflows/go.yml/badge.svg?query=branch%3Amain)
**bip32-typesafe** is a type safe, cryptographically secure implementation of BIP 32 (hierarchical deterministic wallets).

Functions in this implementation let users avoid common mistakes/vulnerablities like:
- mixing private keys and public keys: by type safety (for example, PrivateKey and PublicKey are different types)
- side-channel attacks such as [timing attacks](https://en.wikipedia.org/wiki/Timing_attack): by making functions *constant-time* (taking the same amount of time regardless of the input)

Therefore, this is an easy-to-use and hard-to-misuse library that users can use with confidence.

## Examples
```go
package main

import (
	"crypto/rand"
	"fmt"
	"log"

	bip32 "github.com/koba-e964/bip32-typesafe"
)

func main() {
	// Generate random 32 bytes
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}

	master := bip32.NewMasterKey(seed)
	log.Println(master.PrivateKey())
	child0, err := master.NewChildKey(0) // master/0
	if err != nil {
		panic(err)
	}
	fmt.Println("master/0 =", child0.B58Serialize())
	childH0, err := master.NewChildKey(bip32.FirstHardenedChildIndex + 0) // master/0_H
	if err != nil {
		panic(err)
	}
	fmt.Println("master/0_H =", childH0.B58Serialize())
}
```

## Documentation
Package info: [https://pkg.go.dev/github.com/koba-e964/bip32-typesafe](https://pkg.go.dev/github.com/koba-e964/bip32-typesafe)

## Development
This repo uses pre-commit to run `gofmt` and `staticcheck` before each commit.

```sh
pre-commit install
pre-commit run --all-files
```
