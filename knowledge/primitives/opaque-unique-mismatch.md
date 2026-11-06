# Unique mismatch index of opaque item vectors

Can one private index slot locate the sole unequal raw pair with fewer
executed operations than materializing every equality flag? Compare
the same interleaved opaque witnesses, uniqueness predicate and exact
index output in stack-limited local tapscript. The hypothesis is that
fusing the comparison and index state removes two stack transfers
for most pairs. Allocating that state after consuming the first pair
should preserve the full 500-pair frontier.

The [pinned Bitcoin Core equality implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L886)
compares exact stack item bytes. For every unequal pair, the fused scan
sets the private altstack state to the original index plus one, with
an assertion that the state was zero. The state must be nonzero when
all pairs have been consumed. The fragment returns its value minus one.
The caller specifies vector width and alignment and supplies any
required authentication.

[PR #312](https://github.com/solving-bitcoin/bitcoin-scripts/pull/312)
returns a raw common-prefix length and does not require exactly one
difference after the prefix. [PR #270](https://github.com/solving-bitcoin/bitcoin-scripts/pull/270)
returns the Hamming count on nibbles. The new relation requires count
one for opaque items and returns the index.

The [matched comparison](../comparisons/opaque-unique-mismatch.md)
uses a materialized equality mask with the same raw inputs and
exact returned index. At 500 pairs, the fused check executes
1,507 non-push operations versus 2,505 for the mask and saves
one leaf byte. Both peak at 1,000. The
[negative result](../negative-results/opaque-unique-mismatch.md)
records why eager state initialization loses the last legal pair.
Evidence is `locally-reproduced`; execution is `unclassified`.
