# Strict single peak of signed ScriptNums

Can an ascent count both enforce the one-turn shape and recover
the peak index without per-position constants? Compare arithmetic
and branched phase checks on the same hostile signed values,
strict comparisons and exact peak index. The hypothesis is that
the implication `c != 0 => b == 1` removes branch bytecode without
adding live state.

[Bringmann and coauthors](https://arxiv.org/abs/1806.03217v2)
study strongly unimodal sequences, whose positive parts increase
strictly then decrease strictly. This experiment uses the same
order pattern over signed ScriptNums and requires both sides of the
peak. The [pinned Bitcoin Core implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h#L211)
supplies the four-byte numeric operand domain.

The rightmost edge must descend. Scanning leftward, a zero
ascent count permits either edge direction. A nonzero count
requires ascent at every later step. A positive final count
implies both slopes occur and gives the zero-based peak index.

The existing [nondecreasing nibble predicate](u4-nondecreasing.md)
checks one order relation and returns no peak. [PR #306](https://github.com/solving-bitcoin/bitcoin-scripts/pull/306)
consumes an already-supplied binary mask. Here each comparison
is derived from signed numbers and both slopes are strict.
The [matched comparison](../comparisons/signed-single-peak.md)
and [negative result](../negative-results/signed-single-peak.md)
record the alternatives. See the
[implementation README](../../src/arithmetic/single_peak/README.md).

At width 998, arithmetic phase checking uses 17,946 leaf bytes
versus 20,937 for the branched baseline. It executes 16,943
non-push operations versus 15,950. Both have a 1,000-item peak,
2,993 data-witness bytes and zero hints.

Evidence is `locally-reproduced`. Execution is `unclassified`.
