# Opaque lag-match count

Can a fixed-lag byte-equality count consume one opaque vector using
a constant pick depth while preserving more stack headroom than
an eagerly initialized count? Compare the same raw vector, fixed
non-wrapping lag, exact count and cleanup under local stack-limited
tapscript. The hypothesis is that the first comparison can initialize
the count while the top operand is consumed, saving one live item.

Pinned Bitcoin Core implements
[`OP_PICK`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L759)
and [raw equality](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L886).
The schedule consumes the later member of each pair in reverse
order. The earlier member remains available until its own turn.
Keeping only the count above the surviving input makes the earlier
member's depth constant after the initial comparison.

The existing [cyclic u4 equality mask](u4-cyclic-equality.md)
wraps indices, certifies numeric nibbles and returns one bit per
position. This fragment compares opaque byte strings at unwrapped
indices and returns one count. The
[matched comparison](../comparisons/opaque-lag-count.md)
uses only schedules with this new contract.

See the [implementation and reproduction](../../src/support/lag_count/README.md)
and [eager-state negative result](../negative-results/opaque-lag-count.md).

At width 128 and lag 28, deferred counting uses 618 leaf bytes and
415 executed non-push operations, versus 621 and 417 for eager
counting and 857 and 467 for copying both operands. All three use
365 data-witness bytes and zero hints. Combined peaks are 129, 130,
and 131.

Evidence is `locally-reproduced`; execution is `unclassified`.
