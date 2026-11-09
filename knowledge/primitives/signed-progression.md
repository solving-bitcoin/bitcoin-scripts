# Exact signed ScriptNum arithmetic progression

Does carrying one canonical adjacent difference make an exact signed
progression check smaller than checking the cross-sum identity for every
overlapping triple? Use the same four-byte signed operands, exact
predicate, cleanup, data witness and local tapscript profile. The
hypothesis is that reusing the step removes one arithmetic computation
per overlapping triple.

The [pinned Bitcoin Core ScriptNum definition](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h#L211)
describes the four-byte numeric input limit and wider arithmetic
results. Both schedules guard input width explicitly. The carried
schedule compares the canonical bytes of `x[i] - x[i+1]` to one
stored step, from the end of the witness toward the start. The
cross-sum schedule compares canonical `x[i] + x[i+2]` and
`2*x[i+1]` for every triple. Both predicates characterize an
arithmetic progression over the signed integers.

[PR #304](https://github.com/solving-bitcoin/bitcoin-scripts/pull/304)
compares two independent wide sums and supplies the byte-comparison
technique. [PR #319](https://github.com/solving-bitcoin/bitcoin-scripts/pull/319)
checks a uniform circular step on nibbles. This experiment checks the
unwrapped signed relation across an entire sequence. The
[matched comparison](../comparisons/signed-progression.md) measures
two schedules with that same contract.

The [implementation README](../../src/arithmetic/progression/README.md)
contains all measurements and focused reproduction. The
[negative result](../negative-results/signed-progression.md) shows
why numeric equality can reject a valid wide result.

At 128 values the carried schedule uses 1,400 leaf bytes and 1,145
executed non-push operations versus 1,649 and 1,394 for cross-sums.
Both peak at 130 and use 640 data-witness bytes and zero hints.
At three values the cross-sum schedule wins by one byte and one operation.

Evidence is `locally-reproduced`; execution is `unclassified`.
