# Checked recovery of one erased nibble

Can shifting the public weights by the erased position avoid
reintroducing the missing digit into a second residue check?
Compare the same hostile surviving nibbles, public modulo-17
checks, recovered value and terminal predicate. The hypothesis
is that removing the erased coordinate and centering all other
weights reduces multiplication and reduction costs.

[Reed and Solomon's polynomial codes](https://doi.org/10.1137/0108018)
provide the finite-field coding context. Here the two explicit
parity equations are `S = Σx[i]` and `T = Σi*x[i]` modulo 17.
For public erasure index `e`, the first equation recovers the
missing digit. The second is checked as
`T-e*S = Σ(i-e)*x[i]`. Its coefficient at the erased position
is zero, and all other coefficients are nonzero at widths up
to 17. A single change in the supplied digits therefore fails.

The existing [positional modulo-17 fold](u4-mod17.md)
reduces a base-16 integer. [PR #273](https://github.com/solving-bitcoin/bitcoin-scripts/pull/273)
also delays reduction for positional residues. The present
schedule reduces two bounded arithmetic sums and reconstructs
one erased digit. The second check does not authenticate
arbitrary substitutions.

The [matched comparison](../comparisons/u4-erasure-recovery.md),
[implementation and reproduction](../../src/arithmetic/u4/erasure/README.md)
and [cancellation counterexample](../negative-results/u4-erasure-recovery.md)
record the exact boundary. Evidence is `locally-reproduced`.
Execution is `unclassified`.

At width 17 and erased index eight, centering uses 468 leaf
bytes and 357 executed non-push operations, versus 522 and 405
for recomposition. Peaks are 20 and 21. Both use the same 33
data-witness bytes and zero hints.
