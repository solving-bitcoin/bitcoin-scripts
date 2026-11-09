# Doubling first can lose a valid negabinary value

In the last step of a 32-bit negabinary vector, take the
accumulator `x=1073741824` and bit `d=1`. The exact result
`1-2*x=-2147483647` fits the four-byte signed operand range.
A multiply-first Script computes positive `2147483648`,
which occupies five bytes, then fails when it reparses
that intermediate in subtraction.

The [two-subtraction schedule](../../src/arithmetic/negabinary/README.md)
first computes `1-x=-1073741823` and then subtracts `x` again.
The guarded multiply-first baseline instead handles this
cancellation explicitly. For the same accumulator and bit zero,
the mathematical result is −2,147,483,648 and both checked
schedules reject. Evidence is `locally-reproduced`.
Execution is `unclassified`.
