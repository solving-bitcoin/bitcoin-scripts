# Even-only midpoint equality rejects valid odd sums

The raw equality `a+b = 2*q` accepts `(0,2,q=1)` and rejects
the valid floor midpoint `(-1,0,q=-1)`. In the latter case the
true relation is `a+b = 2*q+1`. Substituting truncation toward
zero instead returns zero and fails the floor predicate.

The [matched comparison](../comparisons/hinted-midpoint.md) also
records the resource cost of an explicit parity item. All preloaded
hints coexist with the ordinary operands. The
[checked implementation](../../src/arithmetic/midpoint/README.md)
derives parity from canonical raw result equality.
At 128 calls, explicit parity still costs 64 fewer combined leaf
and data-witness bytes, while requiring 128 additional hint items.
Evidence is `locally-reproduced`. Execution is `unclassified`.
