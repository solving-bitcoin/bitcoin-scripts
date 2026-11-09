# Unique opaque pair orientation

Can a Script fragment certify which orientation matches two unordered opaque
pairs while keeping fewer live items than an eager evaluation of both matches?
The hypothesis is that one raw equality identifies the only candidate and
lets the script reuse that information to enforce uniqueness on one branch.

For each independently supplied quartet `a b c d`, let straight mean
`a == c && b == d` and reversed mean `a == d && b == c`. If `b == d`, a
straight match needs only `a == c`, but equal members would make both flags
true. Explicitly require `a != b`. If `b != d`, straight is impossible and
checking the two reversed equalities implies distinct members. All four
inputs are hostile raw byte strings. Neither ordering uses numeric payload
coercion, hashes, or witness hints.

The [raw multiset experiment in PR #308](https://github.com/solving-bitcoin/bitcoin-scripts/pull/308)
checks all multiplicities across a full list. This fragment checks each
quartet separately and returns one orientation bit. The
[unique mismatch in PR #329](https://github.com/solving-bitcoin/bitcoin-scripts/pull/329)
returns one changed position between aligned vectors. The existing
[u4 adjacency mask](u4-adjacent-equality.md) checks numeric equality between
neighbors and preserves that representation's numeric semantics.

The [matched comparison](../comparisons/opaque-pair-orientation.md) measures
both schedules on identical raw payloads and output assertions. The
[negative result](../negative-results/opaque-pair-orientation.md) gives the
all-equal ambiguity and explains why a plain existential match is too weak.
See the [implementation README](../../src/support/unique_pair_orientation/README.md)
for stack and profile boundaries. Evidence is `locally-reproduced`.
Execution is `unclassified`.
