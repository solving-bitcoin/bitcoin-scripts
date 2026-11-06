# Carry-out of canonically compressed u32 words

Can Script compute unsigned carry from two compressed u32 witnesses
without expanding either word or invoking a general unsigned comparator?
Compare the same two canonical compressed operands and exact carry
predicate under stack-limited local tapscript execution. The hypothesis
is that summing three small signed classes resolves most cases and
isolates the one case requiring a signed addition.

The [compressed u32 addition](u32-compressed-add.md) adapter defines the
canonical signed ScriptNum wire format and uses byte expansion to return
the wrapped sum. The existing comparator orders the same format. The
new fragment returns the unsigned carry bit only. The
[pinned Bitcoin Core ScriptNum definition](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h#L211)
supplies the numeric width and signed-magnitude encoding constraints.

Tag ordinary nonnegative values with zero, ordinary negative values
with two, and the exact five-byte sentinel with three. Two high-half
words always carry, and neither two low-half words nor a sentinel and
a low-half word can carry. The sum of the tags uniquely identifies the
ordinary mixed case. Its unsigned sum is `2^32` plus the signed sum,
so the carry equals the signed sum's nonnegative predicate.

The [implementation README](../../src/arithmetic/u32/carry/README.md)
records the deterministic fixtures and cost boundary. The
[matched comparison](../comparisons/compressed-u32-carry.md) measures
the sign classes, a complement check with the existing compressed
comparator, and a carry-only expanded ripple. The
[negative result](../negative-results/compressed-u32-carry.md) gives a
collision in consecutive class tags. Evidence is `locally-reproduced`
and execution is `unclassified`.

The sign-class leaf uses 69 bytes versus 153 and 912 for the two
matched baselines. For the first carrying mixed pair, all use 11
serialized data-witness bytes, and the executed counts are 38, 75
and 622 with combined peaks of six, six and eleven.
