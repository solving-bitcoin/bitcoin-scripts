# Positional moment limits and collisions

Allocating three accumulators before the first canonical nibble guard
adds three live items. The eager recurrence peaks at `n+6`, compared
with `n+3` for staged initialization. The width-995 eager fixture
fails with a stack-size error while the staged variant with two
preserved caller items reaches exactly 1,000. An additional caller
item fails there too.

For uncentered nibbles, the largest quadratic moment is
`15*binomial(n,3)`. The all-15 bound is 2,143,435,125 at width 951
and 2,150,211,000 at width 952. Thus width 952 exceeds the largest
positive four-byte ScriptNum and cannot support a later numeric use
of that output under this representation. Centering every nibble
around eight reduces the width-997 magnitude bound to 1,317,395,920.

The three outputs cannot bind the original vector. For example,
`[8,8,8,8]` and `[9,5,11,7]` both pass the all-zero tuple leaf.
Their difference vector `[1,-3,3,-1]` annihilates every polynomial
weight of degree at most two over those four positions.

The [matched fixtures](../../src/arithmetic/u4/binomial_moments/README.md#script-metrics)
show that direct weighting has substantially larger leaves and
traces at width 128. Evidence is `locally-reproduced`; execution is
`unclassified`.
