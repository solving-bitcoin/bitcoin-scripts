# Numeric equality cannot consume a wide ScriptNum result

Replacing `OP_EQUALVERIFY` with `OP_NUMEQUALVERIFY` in the two-sum leaf
compiles to the same six-byte length but changes the accepted domain. For
both `2 * (2³¹−1)` and `−2 * (2³¹−1)`, the arithmetic result needs five
bytes. Bitcoin Core v30.3 rejected the funded numeric-equality spends
with both signs in block and mempool checks. The byte-equality variants
accepted both, at the same complete witness size of 62 bytes. Each uses four
ordinary inputs and zero hints. The funded cases and exact commands are in
the [primitive note](../primitives/scriptnum-equal-sums.md#funded-core-comparison).

The local interpreter at `a09e87af444034698697f0a2267e755cf72f9aed` rejects
the computed positive overflow but accepts the computed negative overflow
under both local profiles. Its
[`topnum` and `popnum` implementation](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/blob/a09e87af444034698697f0a2267e755cf72f9aed/src/data_structures.rs#L131-L193)
checks the positive bound of internally stored numbers. Witness byte vectors
go through a separate bounded parser. This is a diagnostic interpreter
disagreement on the exact numeric-equality leaf. The arithmetic reference
uses canonical byte comparison, so it does not reparse the wide sums.

The explicit carry-limb comparator preserves exactness at both signs, but
for an equality-only consumer it costs 240 script bytes, a peak of seven
items and 95 or 91 executed non-push operations. Byte comparison costs
six bytes, a peak of four and five operations for either sign. Both use
21 serialized data-witness bytes. Carry limbs can feed later arithmetic.
