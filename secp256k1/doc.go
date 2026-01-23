// Package secp256k1 implements secp256k1-related functions and types.
//   - the elliptic curve secp256k1 itself (Compressed, Point and functions with prefix GE)
//   - scalar values (Scalar and functions with prefix SC)
//   - utility functions
//
// This implementation uses complete addition formulas from the paper
// "Complete addition formulas for prime order elliptic curves" (https://eprint.iacr.org/2015/1060.pdf)
// by Renes, Costello, and Batina (2015). These formulas provide constant-time operation
// and handle all cases including point doubling without branches or special cases.
package secp256k1
