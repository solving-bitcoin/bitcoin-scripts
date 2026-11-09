# Sum-based extrema reconstruction can overflow a temporary

For two valid signed inputs `M-1` and `M`, with
`M=2147483647`, both extrema fit in four-byte ScriptNums.
Computing their sum and then subtracting the minimum fails in
the tested local interpreter. The sum is a five-byte numeric
operand at the subsequent subtraction.

The [paired schedule](../../src/arithmetic/extrema/README.md)
compares the two inputs and routes them without computing a sum.
It accepts the same witness. See the
[matched comparison](../comparisons/signed-min-max.md).
Evidence is `locally-reproduced`. Execution is `unclassified`.
