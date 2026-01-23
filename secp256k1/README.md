# secp256k1 Implementation

This package provides a constant-time implementation of the secp256k1 elliptic curve.

## Complete Addition Formulas

This implementation uses **complete addition formulas** from the paper ["Complete addition formulas for prime order elliptic curves"](https://eprint.iacr.org/2015/1060.pdf) by Renes, Costello, and Batina (2015).

### Key Features

- **Projective Coordinates**: Uses Algorithm 7 from the paper for complete addition
  - Handles all cases including point doubling without branches
  - Provides constant-time operation
  - Cost: 12 field multiplications + 2 multiplications by 21

### Performance

Complete addition formulas provide several benefits:
1. **Security**: Constant-time operation prevents timing side-channel attacks
2. **Simplicity**: No special cases or branches needed
3. **Performance**: Competitive with specialized formulas while being simpler

Benchmark results show that projective coordinates with complete formulas (ProjPoint) are faster than Jacobian coordinates for constant-time operations (~1.18ms vs ~1.90ms for scalar multiplication).

## Related projects
https://github.com/decred/dcrd/tree/master/dcrec/secp256k1
