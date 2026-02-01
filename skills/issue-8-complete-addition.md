# Skill: Complete Addition Upgrade (Issue #8)

Purpose: capture what was learned while implementing complete addition formulas
for prime-order short Weierstrass curves in this repo.

## Lessons Learned

- The projective addition in `secp256k1/` already uses the complete formulas
  from the Renes-Costello-Batina paper (ePrint 2015/1060). Reuse it instead
  of re-deriving Jacobian formulas.
- A practical migration path is to convert Jacobian points to the projective
  representation used by `GEProjAdd`, perform the addition, then convert back.
  This keeps the addition complete without changing downstream APIs.
- Scalar multiplication should use the precomputed projective table to ensure
  all additions are complete; remove the unused Jacobian precompute table to
  avoid extra init work.
- Add tests that cover doubling via the complete addition path (A + A) to
  validate completeness beyond distinct-point cases.
- A specialized `GEProjDouble` that replaces multiplications with `feSquare`
  did not improve end-to-end benchmarks on Apple M2; `GEJacobianPoint` and
  `GEProjPoint` benchmarks were slower in a 5x run
  (`go test ./secp256k1 -run=^$ -bench='GEJacobianPoint_|GEProjPoint_' -benchmem -count=5`).
  Main (origin/main @ 7761398): 4206 / 1220375 / 1466087 / 1412107 / 909115 ns/op
  Branch (geprojdouble-only):   5368 / 1276801 / 1487202 / 1445619 / 918919 ns/op
  Delta: +27.63% / +4.62% / +1.44% / +2.37% / +1.08% (same order).

## Implementation Notes (Repo-Specific)

- `jacobianToProj` and `projToJacobian` handle conversions without inversions.
- `GEJacobianAdd` can be implemented as: convert -> `GEProjAdd` -> convert back.
- `GEJacobianPoint` should mirror the constant-time pattern from `GEProjPoint`
  but return Jacobian by converting at the end.
