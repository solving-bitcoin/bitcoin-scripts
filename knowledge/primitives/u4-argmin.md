# Earliest minimum over u4 inputs

Can an order-preserving score remove the branch that updates the value and
position separately, with a lower complete-leaf byte and opcode cost once
setup is amortized? Compare a resident table, per-value constant multiplication,
and a conventional two-register scan on the same hostile nibble vectors.
The hypothesis is that the table saves bytes and operations at larger widths
while the two-register scan uses fewer live stack items.

## Construction

For fixed width `n`, set `P = next_power_of_two(n)` and encode each candidate
as `P * value + index`. For equal values the lower index has the lower score.
For distinct values, a one-unit value change contributes at least `P`, more
than any index difference, so `OP_MIN` implements both comparisons. Score
`16 * P` is above every legal score. A 16-entry table supplies the scaled
value, and four thresholds recover the quotient (nibble) and remainder
(index). The public function consumes canonical ScriptNums and returns both
outputs as canonical ScriptNums. All input items coexist at entry and are
checked before lookup. There are no hints.

The semantic comparator matches the first-minimum behavior in the C++23
working draft [N4950, `[alg.min.max]`](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/n4950.pdf).
The packed Script schedules are the local experiment. The catalog and source
search found checked [sorting](u4-sort.md) and [ordering](u4-nondecreasing.md).
[PR #279](https://github.com/solving-bitcoin/bitcoin-scripts/pull/279) covers a
nibble order statistic. These produce a sorted vector, a monotonicity
predicate, or a selected value, respectively. The experiment measures returning
a minimum with its earliest position on unsorted input.

## Evidence and limits

The [implementation README](../../src/arithmetic/u4/argmin/README.md) gives
all nine matched measurements and reproduction commands. At width 128 the
packed table uses 2,540 leaf bytes and 1,565 executed non-push operations,
versus 2,937 and 1,924 for two registers. The respective combined peaks are
148 and 133. Both use the same 255-byte data witness, 128 ordinary items and
zero hint items. These operations are fixture-specific, and measure counts
of instructions, not time. The [negative result](../negative-results/u4-argmin-schedules.md)
records the width-four loss and composition frontier.

Evidence is `locally-reproduced`; execution is `unclassified`. The local
tapscript profile enables the combined stack limit. No funded or relay
validation is claimed. The caller must bind the same vector if the output
represents a separately committed message.
