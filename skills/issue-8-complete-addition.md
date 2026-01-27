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

## Implementation Notes (Repo-Specific)

- `jacobianToProj` and `projToJacobian` handle conversions without inversions.
- `GEJacobianAdd` can be implemented as: convert -> `GEProjAdd` -> convert back.
- `GEJacobianPoint` should mirror the constant-time pattern from `GEProjPoint`
  but return Jacobian by converting at the end.

