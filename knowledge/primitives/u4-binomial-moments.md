# Centered positional binomial moments over u4

Can a reverse scan compute three exact moments of a nibble vector by
addition and admit more inputs by delaying the accumulator setup? The
hypothesis is that the recurrence reduces leaf bytes and executed
operations against explicit position multipliers, and that staged
initialization avoids three live items during the earliest guards.

## Construction

For canonical nibble `x[i]`, use centered value `c[i] = x[i]-8`. Return
`M0 = sum(c[i])`, `M1 = sum(i*c[i])`, and
`M2 = sum(binomial(i,2)*c[i])`. When the processed suffix starts at
index `j`, its order-`k` accumulator weights `c[i]` by
`binomial(i-j,k)`. Prepending one value shifts every older position
by one. Pascal's recurrence updates the old coefficients by adding
the adjacent lower-order accumulator before inserting the new value.
See the [DLMF binomial identities](https://dlmf.nist.gov/26.3#iii),
version 1.2.8, equations 26.3.5 and 26.3.7.

The first input needs only an unweighted sum, and the second first
needs a linear sum. The quadratic slot is allocated after the third
guard. It lives on the altstack until cleanup. This gives a combined
nonempty peak of `n+3`, including all ordinary inputs and excluding
preserved caller state. Centering limits every accumulator to
`8*binomial(n,k+1)` in magnitude, including a maximum of 1,317,395,920
for the quadratic term at width 997.

[Adler-32](adler32-state.md) has two modular prefix accumulators
over bytes. The [exact nibble sum](u4-exact-sum.md) returns one
unweighted value. The existing [centered projection](u4-centered.md)
uses a signed nibble interpretation, while this relation offsets all
nibbles by eight. Scoped repo and PR searches found no implementation
of this exact three-output relation.

## Evidence and limits

At 128 inputs the staged recurrence uses 2,814 leaf bytes and
2,292 executed non-push operations at peak 131. The eager recurrence
uses 2,832 bytes and 2,307 operations at peak 134. Direct weighting
uses 8,424 bytes and 7,896 operations at peak 139. All include
canonical checks and the same output equality and use 249 serialized
data bytes, 128 ordinary items, and zero hints. The
[implementation README](../../src/arithmetic/u4/binomial_moments/README.md)
gives every measured row and reproduction commands.

Evidence is `locally-reproduced` and execution is `unclassified`.
Different vectors can have all three moments equal. The
[negative results](../negative-results/u4-binomial-moments.md) record
a collision, the eager stack failure, and the uncentered numeric bound.
