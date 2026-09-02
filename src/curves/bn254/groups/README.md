# BN254 groups

G1/G2 point operations and constant-base G1 multi-scalar multiplication.

## Parameters

- Groups: BN254 G1 over `Fq` and G2 over `Fq2`.
- Coordinates: affine; identity and on-curve handling are explicit.
- MSM bases/scalars: caller supplied, equal-length arrays.
- MSM defaults: 8-bit windows and batches of 8 rows.

## Script metrics

The small representative fragments are stack predicates; full hinted point
operations and MSM are input-dependent and substantially larger.

| Fragment | Script size |
| --- | ---: |
| `G1Affine::is_zero()` | <!-- metric:g1_is_zero -->59<!-- /metric:g1_is_zero --> bytes |
| `G2Affine::is_zero_keep_element()` | <!-- metric:g2_is_zero -->224<!-- /metric:g2_is_zero --> bytes |

Maximum stack depth depends on the point operation and MSM batch. MSM tests use
the no-stack-limit executor for oversized research compositions.

## Security

Group operations are secure only when points are canonical, on curve, and in
the required prime-order subgroup. The helpers do not turn unchecked witness
points into safe protocol inputs automatically. BN254 pairing security is
roughly 100 bits.

## Script compatibility and standardness

Small predicates are opcode-compatible broadly. Hinted additions, doublings,
and MSM are intended for tapscript research and often exceed standard legacy or
P2WSH limits. Complete scripts must explicitly verify points/results and clean
the stack.

## Witness and hints

Simple stack predicates need no hints. Hinted point and MSM functions return
ordered field-element hints required by their scripts. MSM scalars and any
non-constant points are also witness inputs; constant bases are embedded.
