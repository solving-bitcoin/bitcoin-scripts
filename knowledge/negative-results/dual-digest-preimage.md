# Reusing the first hash trades Script bytes for SHA-256 work

Computing HASH160 and HASH256 separately is cheaper in locking-script
bytes and executed non-push opcodes. For a 520-byte opening, the native
schedule uses 60 bytes and five operations. Explicit sharing uses 61 and
six. Both have a 524-byte serialized data witness, one data item, zero
hints and a three-item peak. On four preloaded openings the separate
schedule uses 237 bytes and 20 operations, versus 241 and 24 for explicit
sharing. Both use 638 data-witness bytes, four data items, zero hints
and a six-item peak. No Script-size or opcode advantage follows from
doing less compression work.

The shared schedule derives fewer SHA-256 blocks for every opening.
It uses 10 rather than 19 for the 520-byte fixture, and 17 rather than
30 for the four-opening fixture. No wall-clock speed was measured.

Both schedules check the same functions of a common SHA-256 intermediate.
Equal intermediate values imply both final digest values are equal, so
requiring the pair does not yield two independent collision checks.
This statement is about structure, with no security bound.
See the [matched measurement and reproduction](../primitives/dual-digest-preimage.md).
