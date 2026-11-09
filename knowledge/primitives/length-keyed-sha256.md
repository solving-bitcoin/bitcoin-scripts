# Length-keyed SHA-256 opening

Can the preimage itself select a digest slot by exact byte length,
and how does a blocked digest table trade leaf bytes for live stack
items and executed operations? Compare one branch per digest, one
table, and eight-entry tables behind a binary dispatch. All schedules
share the same public dense length range, hostile one-item witness,
SHA-256 predicate, and terminal condition. The hypothesis is that
small tables approach the full table's byte cost without requiring
all digests to coexist on stack.

Pinned Bitcoin Core defines
[`OP_SIZE`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L872)
and
[`OP_SHA256`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L1023).
The generator commits one digest per contiguous length. Runtime
first checks the length window, hashes once, and dispatches on the
exact length. A selected block uses the length minus its first
length as an in-range `OP_ROLL` depth.

The existing [preimage-length commitment](preimage-length.md)
checks one digest and returns a length-derived integer.
[PR #320](https://github.com/solving-bitcoin/bitcoin-scripts/pull/320)
checks two distinct digest openings using witness-selected indices
or an equality scan. This experiment uses one preimage and derives
its digest index without a separate witness item.

See the [matched comparison](../comparisons/length-keyed-sha256.md),
[implementation and reproduction](../../src/commitments/length_keyed/README.md),
and [full-table frontier](../negative-results/length-keyed-sha256.md).

At 521 digests, the 519-byte opening uses 18,070 leaf bytes and
peaks at 10 with eight-entry blocks. The full table uses 17,471
bytes and peaks at 523. Per-digest branching uses 21,744 bytes
and peaks at five. All share 523 serialized data-witness bytes
and zero hints.

Evidence is `locally-reproduced`; execution is `unclassified`.
