# Runtime left rotation of opaque stack items

Can a runtime offset rotate a fixed-width opaque stack suffix without
keeping both input and output vectors live? The hypothesis is that a
single depth into the remaining payloads lets destructive selection
save stack space and script work. Compare against copying selected
items before discarding the original vector, with identical checks
and terminal outputs.

## Construction

A left rotation moves original position `i` to `(i+n-k) mod n`.
The operation has the same sequence semantics as
[C++23 draft N4950, `[alg.rotate]`](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2023/n4950.pdf).
A reverse traversal starts by selecting the last output from depth
`n-k`, wrapping that depth to zero if it equals the current payload
count. After selecting and removing an item, the next predecessor
has the same depth in the shortened vector. Exactly one wrap moves
the traversal from the bottom item to the top of the remainder.
An altstack round trip restores output order.

The existing [checked nibble rotation](u4-vector-rotation.md) uses
a compile-time one-position offset and numeric input checks. The
new fragment takes one canonical runtime offset and preserves raw
bytes. [Stable filtering](stable-selection.md) uses reverse
consumption for a different routing relation. Scoped source and
PR searches found no matched runtime-offset opaque rotation.

## Evidence and limits

At 499 payloads, the destructive route uses 8,856 leaf bytes,
4,999 executed non-push operations and peak 503. The copying
baseline uses 9,749 bytes, 5,749 operations and peak 1,000.
Both receive the same 1,503-byte serialized data witness,
500 ordinary items including the offset, and zero hints.
The [implementation README](../../src/support/rotation/README.md)
includes all measured widths, byte encodings, and reproduction.

Evidence is `locally-reproduced` and execution is `unclassified`.
The destructive route reaches the local limit at width 996.
Output equality can accept several offsets for periodic inputs.
See the [counterexamples and frontier](../negative-results/opaque-runtime-rotation.md).
